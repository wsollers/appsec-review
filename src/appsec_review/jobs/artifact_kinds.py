"""The single typed vocabulary of produced-artifact kinds, and content-based binary roles.

An artifact's ``kind`` is its role in the build (an object, an executable, a static library),
never a raw file-format tag such as ``o``, ``a`` or ``elf``. Where the extension is ambiguous
(no suffix, ``.so.1``, a PIE executable, a ``.dll`` that is an executable) the role comes from
bounded header bytes: the ELF ``e_type`` and program headers, the ``ar`` magic, the PE
characteristics, or the Mach-O file type. The container format is kept separately as
``format`` for consumers that need it.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import struct


class ArtifactKind(str, Enum):
    # Native roles shared by every family that links machine code.
    OBJECT = "object"
    EXECUTABLE = "executable"
    SHARED_LIBRARY = "shared-library"
    STATIC_LIBRARY = "static-library"
    NATIVE_OUTPUT = "native-output"
    NATIVE_EXTENSION = "native-extension"
    NATIVE_ADDON = "native-addon"
    NATIVE_INTERMEDIATE = "native-intermediate"
    NATIVE_SIDE_MODULE = "native-side-module"
    NATIVE_SYMBOLS = "native-symbols"
    LLVM_BITCODE = "llvm-bitcode"
    CLANG_AST = "clang-ast"
    DEBUG_INFORMATION = "debug-information"
    DEBUG_METADATA = "debug-metadata"
    LINK_MAP = "link-map"
    COMPILE_DATABASE = "compile-database"
    GENERATED_SOURCE = "generated-source"
    DEPENDENCY_METADATA = "dependency-metadata"
    INTERMEDIATE = "intermediate"
    # Rust.
    RUST_LIBRARY = "rust-library"
    RUST_METADATA = "rust-metadata"
    CARGO_METADATA = "cargo-metadata"
    # JVM and Android.
    JVM_CLASS = "jvm-class"
    JAR = "jar"
    WAR = "war"
    EAR = "ear"
    DEX = "dex"
    ANDROID_APK = "android-apk"
    ANDROID_INTERMEDIATE = "android-intermediate"
    ANDROID_METADATA = "android-metadata"
    GENERATED_JAVA_SOURCE = "generated-java-source"
    GENERATED_KOTLIN_SOURCE = "generated-kotlin-source"
    KOTLIN_MODULE_METADATA = "kotlin-module-metadata"
    SOURCE_DEBUG_MAP = "source-debug-map"
    JVM_RESOURCE = "jvm-resource"
    METADATA = "metadata"
    # .NET.
    MANAGED_ASSEMBLY = "managed-assembly"
    NUGET_PACKAGE = "nuget-package"
    DEPENDENCY_MANIFEST = "dependency-manifest"
    RUNTIME_CONFIGURATION = "runtime-configuration"
    NUGET_ASSETS = "nuget-assets"
    RESOURCE = "resource"
    BUILD_INTERMEDIATE = "build-intermediate"
    # Node.
    GENERATED_DECLARATION = "generated-declaration"
    SOURCE_MAP = "source-map"
    PACKAGE = "package"
    PACKAGE_INTEGRITY = "package-integrity"
    PACKAGE_METADATA = "package-metadata"
    RESOLVED_DEPENDENCY_METADATA = "resolved-dependency-metadata"
    GENERATED_CODE = "generated-code"
    BUNDLE_ASSET = "bundle-asset"
    # Python and PHP.
    WHEEL = "wheel"
    SOURCE_DISTRIBUTION = "source-distribution"
    BYTECODE = "bytecode"
    GENERATED_AUTOLOAD = "generated-autoload"
    DISTRIBUTABLE_ARCHIVE = "distributable-archive"
    # Go.
    GO_MODULE_METADATA = "go-module-metadata"
    # WebAssembly.
    WASM_MODULE = "wasm-module"
    WASM_COMPONENT = "wasm-component"
    WASM_TEXT = "wasm-text"
    INTERFACE_METADATA = "interface-metadata"
    BINDING = "binding"
    # Generic exchange files.
    TEST_COVERAGE = "test-coverage"
    EXECUTION_PROFILE = "execution-profile"


ARTIFACT_KINDS = frozenset(item.value for item in ArtifactKind)


def require_artifact_kind(value: str) -> str:
    """Return ``value`` when it is in the typed vocabulary; otherwise fail loudly."""
    if value not in ARTIFACT_KINDS:
        raise ValueError(f"artifact kind is outside the typed vocabulary: {value!r}")
    return value


_HEADER_BYTES = 4096
_ET_REL, _ET_EXEC, _ET_DYN, _ET_CORE = 1, 2, 3, 4
_PT_INTERP = 3
_MACHO = {b"\xfe\xed\xfa\xce": ">", b"\xce\xfa\xed\xfe": "<",
          b"\xfe\xed\xfa\xcf": ">", b"\xcf\xfa\xed\xfe": "<"}


def _library_name(name: str) -> bool:
    parts = name.lower().split(".")
    return "so" in parts[1:] or name.lower().endswith((".dylib", ".dll"))


def _elf_role(head: bytes, name: str = "") -> str | None:
    if len(head) < 52 or head[4] not in {1, 2} or head[5] not in {1, 2}:
        return None
    wide, order = head[4] == 2, "<" if head[5] == 1 else ">"
    e_type = struct.unpack_from(order + "H", head, 16)[0]
    if e_type == _ET_REL:
        return ArtifactKind.OBJECT.value
    if e_type == _ET_EXEC:
        return ArtifactKind.EXECUTABLE.value
    if e_type != _ET_DYN:
        return None
    # ET_DYN is both a shared object and a position-independent executable. A dynamically
    # linked executable asks the kernel for a program interpreter; a static-pie executable
    # does not, so without PT_INTERP the shared-object naming convention (`lib.so`,
    # `lib.so.1`) decides.
    fallback = ArtifactKind.SHARED_LIBRARY.value if _library_name(name) else ArtifactKind.EXECUTABLE.value
    if wide:
        if len(head) < 64:
            return fallback
        phoff = struct.unpack_from(order + "Q", head, 32)[0]
        entsize, count = struct.unpack_from(order + "HH", head, 54)
    else:
        phoff = struct.unpack_from(order + "I", head, 28)[0]
        entsize, count = struct.unpack_from(order + "HH", head, 42)
    for index in range(min(count, 64)):
        offset = phoff + index * entsize
        if entsize < 4 or offset + 4 > len(head):
            break
        if struct.unpack_from(order + "I", head, offset)[0] == _PT_INTERP:
            return ArtifactKind.EXECUTABLE.value
    return fallback


def _pe_role(head: bytes) -> str | None:
    if len(head) < 0x40:
        return None
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    if offset + 24 > len(head) or head[offset:offset + 4] != b"PE\0\0":
        return None
    characteristics = struct.unpack_from("<H", head, offset + 22)[0]
    return ArtifactKind.SHARED_LIBRARY.value if characteristics & 0x2000 else ArtifactKind.EXECUTABLE.value


def _macho_role(head: bytes) -> str | None:
    order = _MACHO.get(head[:4])
    if order is None or len(head) < 16:
        return None
    filetype = struct.unpack_from(order + "I", head, 12)[0]
    return {1: ArtifactKind.OBJECT.value, 2: ArtifactKind.EXECUTABLE.value,
            6: ArtifactKind.SHARED_LIBRARY.value, 8: ArtifactKind.SHARED_LIBRARY.value}.get(filetype)


def binary_role(path: Path) -> tuple[str | None, str | None]:
    """Return ``(kind, format)`` from bounded header bytes, or ``(None, None)``.

    Only machine-code containers are classified here; a Java class shares Mach-O's fat
    magic and is left to its family's classifier.
    """
    try:
        with path.open("rb") as stream:
            head = stream.read(_HEADER_BYTES)
    except OSError:
        return None, None
    if head.startswith(b"\x7fELF"):
        # An ELF whose header cannot be read is still a linked candidate; the loader parser
        # downstream names it as a gap rather than this classifier hiding it.
        return _elf_role(head, path.name) or ArtifactKind.EXECUTABLE.value, "elf"
    if head.startswith(b"!<arch>\n"):
        return ArtifactKind.STATIC_LIBRARY.value, "ar"
    if head.startswith(b"MZ"):
        return _pe_role(head), "pe"
    if head[:4] in _MACHO:
        return _macho_role(head), "macho"
    if head.startswith(b"\0asm"):
        return ArtifactKind.WASM_MODULE.value, "wasm"
    return None, None
