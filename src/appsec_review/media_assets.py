"""Central, typed declaration of media and asset file formats no package cataloger can use.

Images, audio, video, fonts, 3D models, textures, and game data archives carry no package metadata,
executable code, or manifests, so per-artifact package catalogers (Syft, and Grype, which catalogs
with Syft) produce nothing for them. ``tool_inputs`` excludes these formats from those tools before
launch; the exclusion is recorded as ``SKIPPED_NA`` with ``INPUT_FORMAT_UNSUPPORTED`` per artifact
and is never evidence that the file is clean.

Recognition is by bounded content first. A suffix is a fallback only when the bytes matched no
recognized executable, object, or archive format, and only for suffixes that name a media format and
nothing else. Suffixes shared with code or manifests (``.obj`` native objects, ``.mod`` for ``go.mod``,
``.ts`` TypeScript, ``.x``, ``.pak``, ``.bin``, ``.dat``) are never a fallback: a Wavefront ``.obj``
must be confirmed by its text directives, and an MPEG transport stream by its sync bytes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
import re
from types import MappingProxyType


class AssetCategory(StrEnum):
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    FONT = "font"
    MODEL = "model"
    TEXTURE = "texture"
    GAME_DATA = "game-data"


@dataclass(frozen=True, slots=True)
class AssetFormat:
    """One media/asset format: decisive magic, a content check, and/or an unambiguous suffix."""

    name: str
    category: AssetCategory
    magic: tuple[tuple[int, bytes], ...] = ()
    content: Callable[[bytes], bool] | None = None
    suffixes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.name):
            raise ValueError(f"asset format name must be a lowercase slug: {self.name}")
        if not (self.magic or self.content or self.suffixes):
            raise ValueError(f"asset format declares no recognition rule: {self.name}")
        if any(not value.startswith(".") or value != value.lower() for value in self.suffixes):
            raise ValueError(f"asset suffixes must be lowercase dotted suffixes: {self.name}")
        if self.suffixes & AMBIGUOUS_SUFFIXES:
            raise ValueError(f"asset format declares an ambiguous suffix fallback: {self.name}")

    @property
    def format(self) -> str:
        """The artifact classification format, namespaced by category (e.g. ``image-png``)."""
        return f"{self.category.value}-{self.name}"

    def matches_content(self, head: bytes) -> bool:
        if any(head[offset:offset + len(value)] == value for offset, value in self.magic):
            return True
        return self.content is not None and self.content(head)


# Suffixes that also name native objects, code, manifests, or generic containers. Declaring one of
# these as a fallback is rejected; such formats are recognized by content only.
AMBIGUOUS_SUFFIXES = frozenset({
    ".obj", ".o", ".mod", ".ts", ".x", ".m", ".pak", ".bin", ".dat", ".raw", ".res", ".asset",
    ".map", ".lib", ".a", ".so", ".dll", ".exe", ".pkg", ".spec",
})


def _riff(form: bytes) -> Callable[[bytes], bool]:
    return lambda head: head[:4] == b"RIFF" and head[8:12] == form


def _iff(*forms: bytes) -> Callable[[bytes], bool]:
    return lambda head: head[:4] == b"FORM" and head[8:12] in forms


_HEIF_BRANDS = frozenset({b"avif", b"avis", b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"})


def _isobmff(head: bytes) -> bool:
    return head[4:8] == b"ftyp" and head[8:12] not in _HEIF_BRANDS


def _heif(head: bytes) -> bool:
    return head[4:8] == b"ftyp" and head[8:12] in _HEIF_BRANDS


def _mpeg_ts(head: bytes) -> bool:
    return len(head) > 376 and head[0] == head[188] == head[376] == 0x47


def _bmp(head: bytes) -> bool:
    return head[:2] == b"BM" and len(head) >= 18 and int.from_bytes(head[14:18], "little") in {
        12, 16, 40, 52, 56, 64, 108, 124}


def _truetype(head: bytes) -> bool:
    if head[:4] not in {b"\0\x01\0\0", b"true"} or len(head) < 12:
        return False
    tables = int.from_bytes(head[4:6], "big")
    if not 1 <= tables <= 128:
        return False
    return int.from_bytes(head[6:8], "big") == 16 * (1 << (tables.bit_length() - 1))


def _text(head: bytes) -> str | None:
    if b"\0" in head[:4096]:
        return None
    try:
        return head[:65536].decode("utf-8")
    except UnicodeDecodeError as exc:
        return head[:exc.start].decode("utf-8") if exc.start > 1024 else None


_WAVEFRONT = re.compile(r"(?:v|vt|vn|vp|f|l|p|o|g|s|mtllib|usemtl)\s")


def _wavefront_obj(head: bytes) -> bool:
    """Wavefront geometry: every meaningful leading line is an OBJ directive, with vertices."""
    text = _text(head)
    if text is None:
        return False
    lines = [line.strip() for line in text.splitlines()[:200]]
    lines = [line for line in lines if line and not line.startswith("#")]
    if len(lines) < 3:
        return False
    return (all(_WAVEFRONT.match(line + " ") for line in lines[:-1]) and
            any(line.startswith("v ") for line in lines))


def _text_prefix(*values: str) -> Callable[[bytes], bool]:
    def check(head: bytes) -> bool:
        text = _text(head)
        return text is not None and text.lstrip("\ufeff \t\r\n").startswith(values)
    return check


_I, _A, _V, _F, _M, _T, _G = (AssetCategory.IMAGE, AssetCategory.AUDIO, AssetCategory.VIDEO,
                              AssetCategory.FONT, AssetCategory.MODEL, AssetCategory.TEXTURE,
                              AssetCategory.GAME_DATA)


def _suffixes(*values: str) -> frozenset[str]:
    return frozenset(values)


ASSET_FORMATS: tuple[AssetFormat, ...] = (
    # Images.
    AssetFormat("png", _I, ((0, b"\x89PNG\r\n\x1a\n"),), suffixes=_suffixes(".png", ".apng")),
    AssetFormat("jpeg", _I, ((0, b"\xff\xd8\xff"),), suffixes=_suffixes(".jpg", ".jpeg", ".jpe", ".jfif")),
    AssetFormat("gif", _I, ((0, b"GIF87a"), (0, b"GIF89a")), suffixes=_suffixes(".gif")),
    AssetFormat("webp", _I, content=_riff(b"WEBP"), suffixes=_suffixes(".webp")),
    AssetFormat("bmp", _I, content=_bmp, suffixes=_suffixes(".bmp", ".dib")),
    AssetFormat("tiff", _I, ((0, b"II*\0"), (0, b"MM\0*")), suffixes=_suffixes(".tif", ".tiff")),
    AssetFormat("icon", _I, suffixes=_suffixes(".ico", ".cur", ".icns")),
    AssetFormat("heif", _I, content=_heif, suffixes=_suffixes(".avif", ".heic", ".heif")),
    AssetFormat("jpeg-xl", _I, ((0, b"\xff\x0a"), (0, b"\0\0\0\x0cJXL \r\n\x87\n")), suffixes=_suffixes(".jxl")),
    AssetFormat("jpeg-2000", _I, ((0, b"\0\0\0\x0cjP  \r\n\x87\n"), (0, b"\xff\x4f\xff\x51")),
                suffixes=_suffixes(".jp2", ".j2k", ".jpx")),
    AssetFormat("photoshop", _I, ((0, b"8BPS"),), suffixes=_suffixes(".psd", ".psb")),
    AssetFormat("gimp", _I, ((0, b"gimp xcf"),), suffixes=_suffixes(".xcf")),
    AssetFormat("openexr", _I, ((0, b"\x76\x2f\x31\x01"),), suffixes=_suffixes(".exr")),
    AssetFormat("radiance-hdr", _I, ((0, b"#?RADIANCE"), (0, b"#?RGBE")), suffixes=_suffixes(".hdr")),
    AssetFormat("qoi", _I, ((0, b"qoif"),), suffixes=_suffixes(".qoi")),
    AssetFormat("xpm", _I, content=_text_prefix("/* XPM */"), suffixes=_suffixes(".xpm")),
    AssetFormat("netpbm", _I, suffixes=_suffixes(".pbm", ".pgm", ".ppm", ".pnm", ".pam")),
    AssetFormat("pcx", _I, suffixes=_suffixes(".pcx")),
    AssetFormat("svg", _I, suffixes=_suffixes(".svg")),
    # Audio.
    AssetFormat("ogg", _A, ((0, b"OggS"),), suffixes=_suffixes(".ogg", ".oga", ".opus", ".spx")),
    AssetFormat("wav", _A, content=_riff(b"WAVE"), suffixes=_suffixes(".wav")),
    AssetFormat("flac", _A, ((0, b"fLaC"),), suffixes=_suffixes(".flac")),
    AssetFormat("mp3", _A, ((0, b"ID3"),), suffixes=_suffixes(".mp3")),
    AssetFormat("aiff", _A, content=_iff(b"AIFF", b"AIFC"), suffixes=_suffixes(".aif", ".aiff", ".aifc")),
    AssetFormat("midi", _A, ((0, b"MThd"),), suffixes=_suffixes(".mid", ".midi")),
    AssetFormat("soundfont", _A, content=_riff(b"sfbk"), suffixes=_suffixes(".sf2")),
    AssetFormat("tracker-module", _A, ((0, b"Extended Module: "), (0, b"IMPM"), (44, b"SCRM")),
                suffixes=_suffixes(".xm", ".it", ".s3m")),
    AssetFormat("aac", _A, suffixes=_suffixes(".aac", ".m4a", ".wma")),
    # Video.
    AssetFormat("matroska", _V, ((0, b"\x1a\x45\xdf\xa3"),), suffixes=_suffixes(".mkv", ".webm", ".mka")),
    AssetFormat("isobmff", _V, content=_isobmff, suffixes=_suffixes(".mp4", ".m4v", ".mov", ".3gp")),
    AssetFormat("avi", _V, content=_riff(b"AVI "), suffixes=_suffixes(".avi")),
    AssetFormat("flv", _V, ((0, b"FLV\x01"),), suffixes=_suffixes(".flv")),
    AssetFormat("mpeg", _V, ((0, b"\0\0\x01\xba"), (0, b"\0\0\x01\xb3")), suffixes=_suffixes(".mpg", ".mpeg")),
    AssetFormat("mpeg-ts", _V, content=_mpeg_ts),
    AssetFormat("asf", _V, ((0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"),), suffixes=_suffixes(".wmv", ".asf")),
    AssetFormat("bink", _V, ((0, b"BIK"), (0, b"KB2")), suffixes=_suffixes(".bik", ".bk2")),
    # Fonts.
    AssetFormat("truetype", _F, content=_truetype, suffixes=_suffixes(".ttf")),
    AssetFormat("opentype", _F, ((0, b"OTTO"),), suffixes=_suffixes(".otf")),
    AssetFormat("font-collection", _F, ((0, b"ttcf"),), suffixes=_suffixes(".ttc", ".otc")),
    AssetFormat("woff", _F, ((0, b"wOFF"), (0, b"wOF2")), suffixes=_suffixes(".woff", ".woff2")),
    AssetFormat("pcf", _F, ((0, b"\x01fcp"),), suffixes=_suffixes(".pcf")),
    AssetFormat("bdf", _F, ((0, b"STARTFONT "),), suffixes=_suffixes(".bdf")),
    AssetFormat("type1", _F, ((0, b"\x80\x01"), (0, b"%!PS-AdobeFont")), suffixes=_suffixes(".pfb", ".pfa")),
    AssetFormat("embedded-opentype", _F, suffixes=_suffixes(".eot")),
    # 3D models and meshes.
    AssetFormat("gltf-binary", _M, ((0, b"glTF"),), suffixes=_suffixes(".glb")),
    AssetFormat("gltf", _M, suffixes=_suffixes(".gltf")),
    AssetFormat("fbx", _M, ((0, b"Kaydara FBX Binary"),), content=_text_prefix("; FBX"),
                suffixes=_suffixes(".fbx")),
    AssetFormat("wavefront-obj", _M, content=_wavefront_obj),
    AssetFormat("wavefront-mtl", _M, suffixes=_suffixes(".mtl")),
    AssetFormat("stl", _M, suffixes=_suffixes(".stl")),
    AssetFormat("ply", _M, ((0, b"ply\n"), (0, b"ply\r\n")), suffixes=_suffixes(".ply")),
    AssetFormat("collada", _M, suffixes=_suffixes(".dae")),
    AssetFormat("blender", _M, ((0, b"BLENDER"),), suffixes=_suffixes(".blend")),
    AssetFormat("usd", _M, ((0, b"PXR-USDC"), (0, b"#usda ")), suffixes=_suffixes(".usd", ".usda", ".usdc")),
    AssetFormat("3ds", _M, suffixes=_suffixes(".3ds", ".max")),
    AssetFormat("directx-x", _M, ((0, b"xof "),)),
    AssetFormat("quake-model", _M, ((0, b"IDPO"), (0, b"IDP2"), (0, b"IDP3"), (0, b"IDSP"), (0, b"IDS2")),
                suffixes=_suffixes(".md2", ".md3", ".mdl")),
    AssetFormat("iqm", _M, ((0, b"INTERQUAKEMODEL\0"),), suffixes=_suffixes(".iqm")),
    AssetFormat("milkshape", _M, ((0, b"MS3D000000"),), suffixes=_suffixes(".ms3d")),
    AssetFormat("lightwave", _M, content=_iff(b"LWO2", b"LWOB", b"LWS2"), suffixes=_suffixes(".lwo", ".lws")),
    AssetFormat("blitz3d", _M, ((0, b"BB3D"),), suffixes=_suffixes(".b3d")),
    # GPU textures.
    AssetFormat("dds", _T, ((0, b"DDS "),), suffixes=_suffixes(".dds")),
    AssetFormat("ktx", _T, ((0, b"\xabKTX 11\xbb\r\n\x1a\n"), (0, b"\xabKTX 20\xbb\r\n\x1a\n")),
                suffixes=_suffixes(".ktx", ".ktx2")),
    AssetFormat("pvr", _T, ((0, b"PVR\x03"),), suffixes=_suffixes(".pvr")),
    AssetFormat("astc", _T, ((0, b"\x13\xab\xa1\x5c"),), suffixes=_suffixes(".astc")),
    AssetFormat("valve-texture", _T, ((0, b"VTF\0"),), suffixes=_suffixes(".vtf")),
    AssetFormat("targa", _T, suffixes=_suffixes(".tga")),
    AssetFormat("basis", _T, suffixes=_suffixes(".basis")),
    # Game data containers (map/texture/sound lumps; no package metadata).
    AssetFormat("doom-wad", _G, ((0, b"IWAD"), (0, b"PWAD"), (0, b"WAD2"), (0, b"WAD3")), suffixes=_suffixes(".wad")),
)


def _index() -> tuple[Mapping[str, AssetFormat], Mapping[str, AssetFormat]]:
    by_format: dict[str, AssetFormat] = {}
    by_suffix: dict[str, AssetFormat] = {}
    for value in ASSET_FORMATS:
        if value.format in by_format:
            raise ValueError(f"duplicate asset format declaration: {value.format}")
        by_format[value.format] = value
        for suffix in value.suffixes:
            if suffix in by_suffix:
                raise ValueError(f"asset suffix declared twice: {suffix}")
            by_suffix[suffix] = value
    return MappingProxyType(by_format), MappingProxyType(by_suffix)


ASSET_FORMATS_BY_FORMAT, ASSET_FORMATS_BY_SUFFIX = _index()
MEDIA_ASSET_FORMATS: frozenset[str] = frozenset(ASSET_FORMATS_BY_FORMAT)
MEDIA_ASSET_FAMILY = "media-asset"


@dataclass(frozen=True, slots=True)
class AssetMatch:
    asset: AssetFormat
    basis: str  # "bounded-magic" or "media-suffix"

    @property
    def format(self) -> str:
        return self.asset.format


def recognize(head: bytes, name: str = "") -> AssetMatch | None:
    """Recognize a media/asset file from bounded bytes, then from an unambiguous suffix.

    Callers must invoke this only after the bytes matched no executable, object, or archive format.
    """
    for value in ASSET_FORMATS:
        if value.matches_content(head):
            return AssetMatch(value, "bounded-magic")
    suffix = PurePosixPath(name).suffix.lower() if name else ""
    if suffix in ASSET_FORMATS_BY_SUFFIX:
        return AssetMatch(ASSET_FORMATS_BY_SUFFIX[suffix], "media-suffix")
    return None
