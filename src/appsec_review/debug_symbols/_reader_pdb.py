"""LLVM pdb2yaml native-PDB normalization; no DIA, symbol server or source reads."""
from __future__ import annotations

import hashlib
import re
import uuid

import yaml
from yaml.events import AliasEvent, MappingStartEvent, SequenceStartEvent, MappingEndEvent, SequenceEndEvent

from appsec_review.debug_symbols._reader_binary import Pe, ReaderFailure
from appsec_review.debug_symbols._reader_codeview import decode_inline_ranges, native_inline_sites
from appsec_review.debug_symbols.contract import AddressRange, RecordKind, SourceSpan, SymbolRecord


_TAGS = {
    "!Lines", "!FileChecksums", "!InlineeLines", "!CrossModuleExports",
    "!CrossModuleImports", "!StringTable", "!FrameData", "!Symbols",
    "!CoffSymbolRVAs", "!Unknown",
}


def _document(text, limits):
    if not text.lstrip().startswith("---") or not text.rstrip().endswith("..."):
        raise ReaderFailure("malformed_tool_output")
    class Loader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            seen = set()
            for key, _ in node.value:
                if not isinstance(key, yaml.ScalarNode) or key.value in seen:
                    raise ReaderFailure("malformed_tool_output")
                seen.add(key.value)
            return super().construct_mapping(node, deep=deep)

    def subsection(loader, tag, node):
        if tag not in _TAGS:
            raise ReaderFailure("unsupported_pdb_yaml_tag")
        result = loader.construct_mapping(node, deep=True)
        result["_kind"] = tag
        return result

    Loader.add_multi_constructor("!", lambda loader, suffix, node: subsection(loader, "!" + suffix, node))
    depth = count = 0
    try:
        # Reject aliases and excessive nesting before allocating the object graph.
        for event in yaml.parse(text, Loader=Loader):
            count += 1
            if count > limits["max_records"] * 64:
                raise ReaderFailure("record_limit")
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                raise ReaderFailure("pdb_yaml_alias_refused")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
                if depth > limits["max_depth"]:
                    raise ReaderFailure("depth_limit")
            if isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                depth -= 1
        result = yaml.load(text, Loader=Loader)
    except yaml.YAMLError as error:
        raise ReaderFailure("malformed_tool_output") from error
    if not isinstance(result, dict):
        raise ReaderFailure("malformed_tool_output")
    return result


_PRIMITIVES = {
    0: "<no type>", 3: "void", 8: "HRESULT", 16: "char", 17: "short", 18: "long",
    19: "long long", 32: "unsigned char", 33: "unsigned short", 34: "unsigned long",
    35: "unsigned long long", 48: "bool", 64: "float", 65: "double",
    112: "char", 113: "wchar_t", 114: "short", 115: "unsigned short",
    116: "int", 117: "unsigned int", 118: "long long", 119: "unsigned long long",
    122: "char16_t", 123: "char32_t",
}


def parse_pdb(text: str, image: Pe, limits, *, native_pdb: bytes | None = None):
    document = _document(text, limits)
    gaps = {"source_paths_unverified", "variable_locations_not_indexed", "signature_parameter_names_unavailable"}
    records = []
    info = document.get("PdbStream", {})
    if not info or "Guid" not in info or "Age" not in info:
        raise ReaderFailure("pdb_export_identity_unavailable")
    if (uuid.UUID(info["Guid"]).bytes_le, info["Age"]) != (image.guid, image.age):
        raise ReaderFailure("pdb_export_identity_mismatch")
    dbi = document.get("DbiStream", {})
    if dbi.get("Age", info["Age"]) != info["Age"]:
        raise ReaderFailure("pdb_export_identity_mismatch")
    tpi = document.get("TpiStream", {}).get("Records", [])
    ipi = document.get("IpiStream", {}).get("Records", [])
    modules = dbi.get("Modules", [])
    if any(not isinstance(value, list) for value in (tpi, ipi, modules)):
        raise ReaderFailure("malformed_tool_output")
    if max(len(tpi), len(ipi), len(modules)) > limits["max_records"]:
        raise ReaderFailure("record_limit")
    types = {0x1000 + index: item for index, item in enumerate(tpi)}
    ids = {0x1000 + index: item for index, item in enumerate(ipi)}
    native_sites = {}
    if native_pdb is not None and any(
        item.get("Kind") in ("S_INLINESITE", "S_INLINESITE2")
        for module in modules for item in module.get("Modi", {}).get("Records", [])
    ):
        try:
            native_sites = native_inline_sites(native_pdb, limits)
        except ReaderFailure as error:
            if error.gap in ("record_limit", "input_limit", "depth_limit"):
                raise
            gaps.add(error.gap)

    def typename(index, seen=()):
        if type(index) is not int or index < 0:
            raise ReaderFailure("malformed_tool_output")
        if index < 0x1000:
            primitive = _PRIMITIVES.get(index & 0xff)
            if primitive is None:
                gaps.add("type_primitive_unavailable")
                return f"<type@{index:x}>"
            return primitive + (" *" if index & 0xf00 else "")
        if index in seen:
            gaps.add("types_recursive_reference")
            return f"<type@{index:x}>"
        if len(seen) >= limits["max_depth"]:
            raise ReaderFailure("depth_limit")
        item = types.get(index)
        if not item:
            gaps.add("types_reference_unavailable")
            return f"<type@{index:x}>"
        for key in ("Class", "Union", "Enum", "Array"):
            if key in item and item[key].get("Name"):
                return item[key]["Name"]
        if "Pointer" in item:
            return typename(item["Pointer"]["ReferentType"], (*seen, index)) + " *"
        if "Modifier" in item:
            value = item["Modifier"]
            return " ".join(str(flag).lower() for flag in value.get("Modifiers", [])) + " " + typename(value["ModifiedType"], (*seen, index))
        if item.get("Kind") in ("LF_PROCEDURE", "LF_MFUNCTION"):
            return f"<function@{index:x}>"
        gaps.add("type_name_unavailable")
        return f"<type@{index:x}>"

    def signature(index, is_id=False):
        if is_id:
            value = ids.get(index, {})
            value = value.get("FuncId", value.get("MemberFuncId", {}))
            index = value.get("FunctionType")
        item = types.get(index, {})
        procedure = item.get("Procedure", item.get("MemberFunction"))
        if not procedure:
            gaps.add("function_signature_unavailable")
            return None
        arguments = types.get(procedure.get("ArgumentList"), {}).get("ArgList", {}).get("ArgIndices")
        if arguments is None:
            gaps.add("function_parameters_unavailable")
            arguments = []
        return {
            "return_type": typename(procedure.get("ReturnType", 0)),
            "parameter_types": [typename(arg) for arg in arguments],
            "calling_convention": procedure.get("CallConv"),
            "parameter_count": procedure.get("ParameterCount"),
        }

    def fields(index, seen=()):
        if index == 0:
            return []
        if index in seen:
            raise ReaderFailure("pdb_type_cycle")
        if len(seen) >= limits["max_depth"]:
            raise ReaderFailure("depth_limit")
        value = types.get(index, {}).get("FieldList")
        if value is None:
            gaps.add("type_fields_unavailable")
            return []
        result = []
        for item in value:
            kind = item.get("Kind")
            if kind in ("LF_MEMBER", "LF_BCLASS"):
                value = item.get("DataMember", item.get("BaseClass", {}))
                offset = value.get("FieldOffset", value.get("Offset"))
                if type(offset) is not int or offset < 0:
                    gaps.add("type_member_location_unavailable")
                    offset = None
                member = {"name": value.get("Name", ""), "offset": offset,
                          "type": typename(value.get("Type", 0))}
                bitfield = types.get(value.get("Type"), {}).get("BitField")
                if bitfield:
                    member.update(bit_size=bitfield.get("BitSize"), data_bit_offset=bitfield.get("BitOffset"))
                result.append(member)
            elif kind in ("LF_INDEX", "LF_LISTCONTINUATION"):
                continuation = item.get("ListContinuation", {})
                result.extend(fields(continuation["ContinuationIndex"], (*seen, index)))
            elif kind == "LF_ENUMERATE":
                value = item.get("Enumerator", {})
                result.append({"name": value.get("Name", ""), "value": value.get("Value")})
            else:
                gaps.add("type_layout_member_unsupported")
            if len(result) > limits["max_records"]:
                raise ReaderFailure("record_limit")
        return result

    for index, item in types.items():
        kind = item.get("Kind", "")
        layout = item.get("Class", item.get("Union", item.get("Enum", item.get("Array"))))
        if layout is None:
            if kind not in ("LF_FIELDLIST", "LF_PROCEDURE", "LF_MFUNCTION", "LF_ARGLIST",
                            "LF_POINTER", "LF_MODIFIER", "LF_BITFIELD"):
                gaps.add("type_record_unsupported")
            continue
        if "ForwardReference" in layout.get("Options", []):
            continue
        records.append(SymbolRecord(
            f"pdb:tpi:{index:08x}", RecordKind.TYPE_LAYOUT, layout.get("Name", ""),
            data={"type_index": index, "type_kind": kind, "byte_size": layout.get("Size"),
                  "members": fields(layout.get("FieldList", 0))},
        ))

    for module_index, module in enumerate(modules):
        module_key = f"pdb:module:{module_index:08x}"
        subsections = module.get("Subsections", [])
        checksums, inlinees = {}, {}
        for sub in subsections:
            if sub.get("_kind") == "!FileChecksums":
                for value in sub.get("Checksums", []):
                    checksum, algorithm = value.get("Checksum", ""), value.get("Kind", "").lower()
                    expected = {"md5": 32, "sha1": 40, "sha256": 64}.get(algorithm)
                    if algorithm == "none":
                        continue
                    if expected is None:
                        gaps.add("source_checksum_unsupported")
                        continue
                    if not isinstance(checksum, str) or not re.fullmatch(r"[a-fA-F0-9]{" + str(expected) + r"}", checksum):
                        raise ReaderFailure("malformed_tool_output")
                    checksums[value["FileName"]] = (checksum.lower(), algorithm)
            elif sub.get("_kind") == "!InlineeLines":
                for site in sub.get("Sites", []):
                    inlinees[site["Inlinee"]] = site
            elif sub.get("_kind") not in ("!Lines", "!FileChecksums", "!InlineeLines"):
                gaps.add("pdb_subsection_unsupported")

        def source(path, line, column=0):
            digest, algorithm = checksums.get(path, (None, None))
            return SourceSpan(path, line, column, digest, algorithm)

        module_symbols = module.get("Modi", {}).get("Records", [])
        compile_metadata = next((item["Compile3Sym"] for item in module_symbols if "Compile3Sym" in item), {})
        if module.get("SourceFiles") or module.get("ObjFile"):
            recorded_module = module.get("Module", "")
            records.append(SymbolRecord(
                module_key, RecordKind.COMPILATION_UNIT, re.split(r"[/\\]", recorded_module)[-1],
                data={"module_index": module_index,
                      "module_name_sha256": hashlib.sha256(recorded_module.encode("utf-8")).hexdigest(),
                      "source_names_sha256": [hashlib.sha256(path.encode("utf-8")).hexdigest()
                                              for path in module.get("SourceFiles", [])],
                      "producer": compile_metadata.get("Version", ""), "source_binding": "path_only"},
            ))
        stack = []
        procedures = {}
        inline_ranges = {}
        for symbol_index, item in enumerate(module_symbols):
            kind = item.get("Kind", "")
            key = module_key + f":symbol:{symbol_index:08x}"
            if kind in ("S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID"):
                procedure = item["ProcSym"]
                size = procedure["CodeSize"]
                start = image.rva(procedure["Segment"], procedure["Offset"], size)
                ranges = (AddressRange(start, start + size),) if size else ()
                if not size:
                    gaps.add("functions_without_address_ranges")
                records.append(SymbolRecord(
                    key, RecordKind.SYMBOL, procedure.get("DisplayName", ""), ranges,
                    parent_key=module_key,
                    data={"signature": signature(procedure["FunctionType"], kind.endswith("_ID")),
                          "address_kind": "rva", "module_index": module_index,
                          "native_record_index": symbol_index},
                ))
                stack.append((key, "function"))
                procedures[key] = procedure
                if "HasOptimizedDebugInfo" in procedure.get("Flags", []):
                    gaps.add("optimized_debug_information")
            elif kind in ("S_INLINESITE", "S_INLINESITE2"):
                inline = item["InlineSiteSym"]
                value = ids.get(inline["Inlinee"], {})
                identity = value.get("FuncId", value.get("MemberFuncId", {}))
                site = inlinees.get(inline["Inlinee"], {})
                ranges = ()
                native = native_sites.get((module_index, symbol_index))
                try:
                    if native is None:
                        raise ReaderFailure("inline_native_data_unavailable")
                    procedure_key = module_key + f":symbol:{native.procedure_index:08x}"
                    parent_key = module_key + f":symbol:{native.parent_index:08x}"
                    active_procedure = next((entry[0] for entry in reversed(stack) if entry[1] == "function"), None)
                    if (native.parent != inline["PtrParent"] or native.end != inline["PtrEnd"]
                            or native.inlinee != inline["Inlinee"]
                            or not stack or parent_key != stack[-1][0]
                            or procedure_key != active_procedure
                            or any(procedures.get(procedure_key, {}).get(field) != value
                                   for field, value in native.procedure.items())):
                        raise ReaderFailure("inline_native_export_mismatch")
                    relative = decode_inline_ranges(
                        native.annotations, procedure_size=native.procedure["CodeSize"],
                        max_records=limits["max_records"],
                    )
                    start = image.rva(native.procedure["Segment"], native.procedure["Offset"],
                                      native.procedure["CodeSize"])
                    ranges = tuple(AddressRange(start + interval.start, start + interval.end)
                                   for interval in relative)
                    if parent_key in inline_ranges and any(
                        not any(parent.start <= interval.start and interval.end <= parent.end
                                for parent in inline_ranges[parent_key])
                        for interval in ranges
                    ):
                        ranges = ()
                        raise ReaderFailure("inline_annotation_parent_range_mismatch")
                except ReaderFailure as error:
                    if error.gap in ("record_limit", "input_limit", "depth_limit"):
                        raise
                    gaps.update(("inline_ranges_unavailable", error.gap))
                records.append(SymbolRecord(
                    key, RecordKind.INLINE_FRAME, identity.get("Name", ""),
                    ranges=ranges,
                    source=source(site["FileName"], site["LineNum"]) if site else None,
                    parent_key=stack[-1][0] if stack else module_key,
                    data={"inlinee_index": inline["Inlinee"], "address_kind": "rva",
                          "source_role": "inlinee_definition", "source_binding": "path_only",
                          "native_record_offset": native.record_offset if native else None},
                ))
                inline_ranges[key] = ranges
                stack.append((key, "inline"))
            elif kind in ("S_BLOCK32", "S_SEPCODE"):
                stack.append((stack[-1][0] if stack else module_key, "block"))
            elif kind in ("S_END", "S_PROC_ID_END", "S_INLINESITE_END"):
                if stack:
                    stack.pop()
            elif kind in ("S_THUNK32", "S_TRAMPOLINE", "S_LPROC32_DPC", "S_GPROC32_DPC"):
                gaps.add("function_record_unsupported")
            if len(stack) > limits["max_depth"]:
                raise ReaderFailure("depth_limit")
            if kind.startswith("S_DEFRANGE"):
                gaps.add("location_expressions_not_evaluated")
            if kind == "S_LOCAL" and "IsOptimizedOut" in item.get("LocalSym", {}).get("Flags", []):
                gaps.add("optimized_debug_information")

        for section_index, sub in enumerate(subsections):
            if sub.get("_kind") != "!Lines":
                continue
            size, offset, segment = sub["CodeSize"], sub["RelocOffset"], sub["RelocSegment"]
            base = image.rva(segment, offset, size)
            rows = []
            for block_index, block in enumerate(sub.get("Blocks", [])):
                columns = block.get("Columns", [])
                for row_index, row in enumerate(block.get("Lines", [])):
                    column = columns[row_index].get("StartColumn", 0) if row_index < len(columns) else 0
                    rows.append((row["Offset"], row["LineStart"], column, block["FileName"], block_index, row_index))
            rows.sort(key=lambda row: (row[0], row[4], row[5]))
            for index, (start, line, column, path, block_index, row_index) in enumerate(rows):
                end = rows[index + 1][0] if index + 1 < len(rows) else size
                if not 0 <= start <= end <= size:
                    raise ReaderFailure("pdb_invalid_address")
                if start == end or line == 0:
                    continue
                records.append(SymbolRecord(
                    module_key + f":lines:{section_index}:{block_index}:{row_index}", RecordKind.SOURCE_RANGE,
                    ranges=(AddressRange(base + start, base + end),), source=source(path, line, column),
                    parent_key=module_key, data={"source_binding": "path_only", "address_kind": "rva"},
                ))
                if len(records) > limits["max_records"]:
                    raise ReaderFailure("record_limit")
        if len(records) > limits["max_records"]:
            raise ReaderFailure("record_limit")

    publics = document.get("PublicsStream", {}).get("Records", [])
    if publics:
        gaps.add("public_symbols_have_no_lengths_or_signatures")
    if not any(record.kind is RecordKind.SYMBOL for record in records):
        # Public-only PDBs retain names and RVAs, without inventing a one-byte range.
        for index, item in enumerate(publics):
            value = item.get("PublicSym32", {})
            if not value:
                gaps.add("public_symbol_record_unsupported")
                continue
            records.append(SymbolRecord(
                f"pdb:public:{index:08x}", RecordKind.SYMBOL, value.get("Name", ""),
                data={"rva": image.rva(value["Segment"], value["Offset"], 0),
                      "address_kind": "rva", "signature": None, "public_only": True},
            ))
        gaps.add("function_ranges_unavailable")
    for kind, gap in ((RecordKind.COMPILATION_UNIT, "compilation_units_unavailable"),
                      (RecordKind.TYPE_LAYOUT, "type_layouts_unavailable"),
                      (RecordKind.SOURCE_RANGE, "source_ranges_unavailable"),
                      (RecordKind.INLINE_FRAME, "inline_frames_not_emitted")):
        if not any(record.kind is kind for record in records):
            gaps.add(gap)
    if any(record.kind is RecordKind.SOURCE_RANGE and record.source and not record.source.checksum
           for record in records):
        gaps.add("source_checksums_unavailable")
    return records, gaps
