"""Pinned offline B13 toolchain for the E04/E05 LLVM evidence workers."""
from __future__ import annotations

import tunables
from datetime import datetime, timezone
import json
import re
from pathlib import Path, PurePosixPath
import threading
from typing import Any

import container_execution as ce
from execution_state import (Blocked, atomic_bytes, atomic_json, beneath, data_path, digest, file_hash, identifier,
                             read_json)
import item_memo
import permission_capabilities as pc

RECEIPT = "b13-receipts.json"
MAX_IR_BYTES = 64 * 1024 * 1024


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _permission(run_id: str, job: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job,
                   "capabilities": []}
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked("IR evidence: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=[], clock=_utc, cancel=threading.Event())


def _record_path(image_id: str) -> Path:
    candidates = [ce.IMAGES_DIR / f"{image_id}.json"]
    if image_id.startswith("image_build_"):
        candidates.append(ce.BUILD_IMAGES_DIR / f"{image_id}.json")
    present = [path for path in candidates if path.is_file() and not path.is_symlink()]
    if len(present) != 1:
        raise Blocked("IR evidence image record is missing or ambiguous")
    return present[0]


def capture_images(inputs: dict[str, Any]) -> list[str]:
    """ADR-0014: IR capture serves every build image its units used (e.g. noble and the resolute
    fallback), one toolchain per image, each bound to its accepted native-build record."""
    return sorted({unit["image_id"] for unit in inputs["upstream_result"]["units"]})


def _image(inputs: dict[str, Any], job: str, image_id: str | None = None) -> tuple[str, str, str, dict[str, Any]]:
    if job == "02-ir-capture":
        units = inputs["upstream_result"]["units"]
        image_id = image_id if image_id is not None else capture_images(inputs)[0]
        mine = [unit for unit in units if unit["image_id"] == image_id]
        bindings_by_unit = dict(inputs["toolchain_bindings"])
        identities = {(unit["image_id"], unit["image_digest"]) for unit in mine}
        bindings = {bindings_by_unit.get(unit["unit_id"]) for unit in mine}
        accepted_records = {iid: binding for iid, binding in inputs["toolchain_records"]}
        if len(identities) != 1 or len(bindings) != 1 or not isinstance(next(iter(bindings)), str):
            raise Blocked(f"IR capture: image {image_id} is not one exact native-build image generation")
        image_digest = next(iter(identities))[1]; toolchain_sha = next(iter(bindings))
    elif job == "02-ir-link":
        from ir_evidence import link_selection
        accepted_records = None
        upstream = inputs["upstream_result"]
        primary, selected, _gaps = link_selection(upstream)
        identities = {(item["image_id"], item["image_digest"]) for item in upstream["variants"]
                      if item["variant_sha256"] == primary}
        bindings = {item["toolchain_sha256"] for item in selected}
        if len(identities) != 1 or len(bindings) != 1:
            raise Blocked("IR link requires one exact capture image generation per link target")
        image_id, image_digest = next(iter(identities)); toolchain_sha = next(iter(bindings))
    else:
        accepted_records = None
        upstream = inputs["upstream_result"]
        image_id, image_digest = upstream["image_id"], upstream["image_digest"]
        toolchain_sha = upstream["toolchain_sha256"]
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    record = registry.get(image_id)
    if record is None or record.get("digest") != image_digest:
        raise Blocked("IR evidence image is absent or differs from the accepted build generation")
    record_path = _record_path(image_id)
    if (read_json(record_path) != record or "sha256:" + file_hash(record_path) != toolchain_sha):
        raise Blocked("IR evidence image record hash differs from the accepted build generation")
    if job == "02-ir-capture":
        binding = accepted_records.get(image_id)
        if (not isinstance(binding, dict) or binding.get("value") != record or
                binding.get("sha256") != toolchain_sha or not toolchain_sha.startswith("sha256:")):
            raise Blocked("IR capture image record differs from the accepted native-build generation")
    return image_id, image_digest, toolchain_sha, record


class B13IrToolchain:
    def __init__(self, job: str, inputs: dict[str, Any], attempt: Path):
        self.job, self.inputs, self.attempt = job, inputs, attempt
        self.run_id = inputs["run_id"]
        self.images = ({image: _image(inputs, job, image) for image in capture_images(inputs)}
                       if job == "02-ir-capture" else None)
        self.image_id, self.image_digest, self.toolchain_sha256, self.image_record = _image(inputs, job)
        self.runtime = _runtime(inputs["source_snapshot_sha256"])
        self.receipts: list[dict[str, Any]] = []
        self.target = Path(inputs["target_path"]) if job == "02-ir-capture" else None
        # Brief N / ADR-0014 item 6: one B13 run per clang invocation (capture), per link or per
        # disassembly; an unchanged operation reuses its earlier verified trial in its owner attempt.
        self.memo = item_memo.Memo("ir:" + job)

    def select(self, image_id: str) -> None:
        """Capture only: compile the next unit's entries with that unit's build image."""
        if not self.images or image_id not in self.images:
            raise Blocked(f"IR capture image {image_id} is not an accepted native-build image")
        self.image_id, self.image_digest, self.toolchain_sha256, self.image_record = self.images[image_id]

    def _request(self, attempt_id: str, argv: list[str], mounts: list[dict[str, str]]) -> dict[str, Any]:
        return {"schema": ce.REQUEST_ID, "run_id": self.run_id, "job_id": self.job,
            "attempt_id": attempt_id, "image": {"image_id": self.image_id, "digest": self.image_digest},
            "argv": argv, "environment": [{"name":"LANG","value":"C"},
                {"name":"LC_ALL","value":"C"},{"name":"NO_COLOR","value":"1"}],
            "target_mounts": mounts, "scratch_path":"scratch", "log_path":"logs/container",
            "network":{"mode":"none","destinations":[]},
            "permission":_permission(self.run_id,self.job,self.inputs["source_snapshot_sha256"],_utc()),
            "limits":tunables.container_limits(self.job)}

    def _memo_material(self, operation: str, request: dict[str, Any], output: str) -> dict[str, Any]:
        """The operation's own inputs: today's request minus attempt id, permission and mount host
        paths, and the content behind each mount, hashed here: the attested checkout identity for
        /workspace, and for an upstream attempt mount the sha256 of every file the argv names in it."""
        contents = {}
        for mount in request["target_mounts"]:
            path = mount["container_path"]
            if path == "/workspace":
                contents[path] = self.inputs["source_tree_sha256"]
                continue
            named = sorted(word for word in request["argv"] if word.startswith(path + "/"))
            if not named:
                raise ValueError("an input mount the argv never names cannot be keyed")
            host = Path(mount["host_path"])
            contents[path] = {word: "sha256:" + file_hash(beneath(host, host / word[len(path) + 1:]))
                              for word in named}
        defaults = ce.host_defaults()
        return {"run_id": self.run_id, "job": self.job, "operation": operation, "output": output,
                "toolchain_sha256": self.toolchain_sha256,
                **{key: value for key, value in request.items()
                   if key not in ("attempt_id", "permission", "target_mounts")},
                "container_paths": [m["container_path"] for m in request["target_mounts"]],
                "contents": contents, "boundary_sha256": ce.boundary_sha256(),
                "host": {"host_flavor": defaults["host_flavor"], "docker_executable": str(defaults["docker_executable"]),
                         "container_user": defaults["container_user"]}}

    def _from_memo(self, entry: dict[str, Any], operation: str, request: dict[str, Any],
                   output: str) -> tuple[dict[str, Any], Path]:
        """Re-verify a memoised trial in its owner attempt; returns its receipt and output path."""
        base = self.attempt.parent
        owner = beneath(base, base / identifier(entry["owner_attempt_id"]))
        if owner == self.attempt or not owner.is_dir():
            raise ValueError("memo owner attempt is absent or is this attempt")
        if not re.fullmatch(r"tools/[0-9]{4}-" + operation, entry["trial_path"]):
            raise ValueError("memoised trial path is not a tool trial of this operation")
        trial = beneath(owner, owner / entry["trial_path"])
        recorded = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        item_memo.same_b13_request(recorded, request, adapter_id=entry["adapter_attempt_id"])
        item_memo.recorded_permission_granted(recorded["permission"], run_id=self.run_id, job_id=self.job,
            requirement=request["permission"]["requirement"], registry_ceiling=[])
        verified = ce.load_verified_result(trial, run_id=self.run_id, job_id=self.job,
            attempt_id=entry["adapter_attempt_id"], request=recorded, images_dir=self.runtime.images_dir,
            expected_result_sha256=entry["expected_result_sha256"], **_host(self.runtime))
        if verified["execution_status"] != "OK":
            raise ValueError("memoised trial did not complete OK")
        raw = trial / "scratch" / output
        if not raw.is_file() or raw.is_symlink() or "sha256:" + file_hash(raw) != entry["output_sha256"]:
            raise ValueError("memoised tool output differs from its retained hash")
        receipt = {"operation": operation, "adapter_attempt_id": entry["adapter_attempt_id"],
                   "trial_path": entry["trial_path"], "expected_result_sha256": entry["expected_result_sha256"],
                   "output_path": "scratch/" + output, "output_sha256": entry["output_sha256"],
                   "execution_status": "OK", "owner_attempt_id": owner.name}
        return receipt, raw

    def _run(self, operation: str, argv: list[str], mounts: list[dict[str, str]], output: str | None) -> tuple[int, Path]:
        material = None
        if self.memo.enabled and output is not None:
            probe = self._request("memo-probe", argv, mounts)
            try:
                material = self._memo_material(operation, probe, output)
            except (OSError, ValueError, KeyError):
                material = None
            if material is not None:
                hit = self.memo.lookup(material, lambda entry: self._from_memo(entry, operation, probe, output))
                if hit is not None:
                    receipt, raw = hit
                    self.receipts.append(receipt)
                    return 0, raw
        ordinal = len(self.receipts) + 1
        adapter_id = f"{self.job.removeprefix('02-ir-')}-{ordinal:04d}-{self.attempt.name[:8]}"
        trial = self.attempt / "tools" / f"{ordinal:04d}-{operation}"
        trial.mkdir(parents=True)
        request = self._request(adapter_id, argv, mounts)
        terminal = ce.run_container(self.runtime, run_id=self.run_id, job_id=self.job,
            attempt_id=adapter_id, attempt_root=trial, request=request)
        expected = terminal["result_sha256"]
        ce.load_verified_result(trial, run_id=self.run_id, job_id=self.job, attempt_id=adapter_id,
            request=request, images_dir=self.runtime.images_dir, expected_result_sha256=expected,
            **_host(self.runtime))
        raw = trial / "scratch" / output if output else trial / "logs" / "container" / "stdout.log"
        raw_sha = "sha256:" + file_hash(raw) if raw.is_file() and not raw.is_symlink() else None
        self.receipts.append({"operation":operation,"adapter_attempt_id":adapter_id,
            "trial_path":trial.relative_to(self.attempt).as_posix(),"expected_result_sha256":expected,
            "output_path":("scratch/"+output) if output else "logs/container/stdout.log",
            "output_sha256":raw_sha,"execution_status":terminal["execution_status"]})
        if material is not None and terminal["execution_status"] == "OK" and raw_sha is not None:
            # only complete outputs are memoised; a failed compile is retried next attempt
            self.memo.record(material, {"owner_attempt_id": self.attempt.name,
                "trial_path": trial.relative_to(self.attempt).as_posix(), "adapter_attempt_id": adapter_id,
                "expected_result_sha256": expected, "output_sha256": raw_sha})
        return (0 if terminal["execution_status"] == "OK" else 1), raw

    def compile(self, argv: list[str], source: Path, destination: Path) -> int:
        assert self.target is not None
        try:
            relative = source.resolve(strict=True).relative_to(self.target.resolve(strict=True)).as_posix()
        except (OSError, ValueError) as exc:
            raise Blocked("IR capture source leaves the accepted checkout") from exc
        rendered=[]; index=0
        while index < len(argv):
            word=argv[index]
            if index == 0:
                rendered.append(word)
            elif word == "-o":
                rendered.extend(["-o","/scratch/module.bc"]); index += 1
            elif word in {relative, "/scratch/src/"+relative}:
                rendered.append("/workspace/"+relative)
            elif word.startswith("/scratch/src/"):
                rendered.append("/workspace/"+word.removeprefix("/scratch/src/"))
            elif word == "-I.": rendered.append("-I/workspace")
            elif word.startswith("-I") and len(word)>2 and not word[2:].startswith("/"):
                rendered.append("-I/workspace/"+word[2:])
            else: rendered.append(word)
            index += 1
        code, raw = self._run("compile", rendered,
            [{"host_path":str(self.target),"container_path":"/workspace"}], "module.bc")
        if code == 0:
            if raw.stat().st_size > tunables.value(self.job, "ir_max_bytes"):
                raise RuntimeError("compiled bitcode exceeds the ir_max_bytes tunable")
            data=raw.read_bytes()
            if data[:4] != b"BC\xc0\xde": raise RuntimeError("pinned compiler emitted malformed bitcode")
            atomic_bytes(destination,data)
        return code

    def link(self, modules: list[Path], destination: Path) -> int:
        capture_attempt = data_path(self.run_id,"jobs","02-ir-capture","attempts",
                                    self.inputs["upstream"]["attempt_id"])
        rendered=[]
        for module in modules:
            try: rendered.append("/inputs/capture/"+module.resolve(strict=True).relative_to(capture_attempt.resolve(strict=True)).as_posix())
            except (OSError,ValueError) as exc: raise Blocked("IR link input leaves its accepted capture attempt") from exc
        argv=["/opt/llvm/bin/llvm-link",*rendered,"-o","/scratch/linked.bc"]
        code,raw=self._run("link",argv,[{"host_path":str(capture_attempt),"container_path":"/inputs/capture"}],"linked.bc")
        if code==0:
            if raw.stat().st_size > MAX_IR_BYTES:
                raise RuntimeError("linked bitcode exceeds the 64 MiB bound")
            data=raw.read_bytes()
            if data[:4]!=b"BC\xc0\xde": raise RuntimeError("pinned linker emitted malformed bitcode")
            atomic_bytes(destination,data)
        return code

    def disassemble(self, module: Path) -> str:
        link_attempt=data_path(self.run_id,"jobs","02-ir-link","attempts",self.inputs["upstream"]["attempt_id"])
        try: relative=module.resolve(strict=True).relative_to(link_attempt.resolve(strict=True)).as_posix()
        except (OSError,ValueError) as exc: raise Blocked("IR facts input leaves its accepted link attempt") from exc
        code,raw=self._run("disassemble",["/opt/llvm/bin/llvm-dis","/inputs/link/"+relative,"-o","/scratch/module.ll"],
            [{"host_path":str(link_attempt),"container_path":"/inputs/link"}],"module.ll")
        if code: raise RuntimeError("pinned llvm-dis failed")
        if raw.stat().st_size > tunables.value(self.job, "ir_max_bytes"): raise RuntimeError("disassembled IR exceeds the ir_max_bytes tunable")
        return raw.read_text(encoding="utf-8")

    def publish_receipts(self) -> None:
        document = {"schema":"appsec-review/ir-b13-receipts/1.0",
            "run_id":self.run_id,"job_id":self.job,"image_id":self.image_id,
            "image_digest":self.image_digest,"toolchain_sha256":self.toolchain_sha256,
            "operations":self.receipts}
        if self.images:
            first = sorted(self.images)[0]
            document.update(image_id=first, image_digest=self.images[first][1],
                            toolchain_sha256=self.images[first][2],
                            images=[{"image_id":i,"image_digest":v[1],"toolchain_sha256":v[2]}
                                    for i, v in sorted(self.images.items())])
        atomic_json(self.attempt / RECEIPT, document)


def factory(job: str, inputs: dict[str, Any], attempt: Path) -> B13IrToolchain:
    return B13IrToolchain(job,inputs,attempt)


def validate_receipts(job: str, inputs: dict[str, Any], attempt: Path) -> None:
    document=read_json(attempt/RECEIPT)
    image_id,image_digest,toolchain_sha,_record=_image(inputs,job)
    keys={"schema","run_id","job_id","image_id","image_digest","toolchain_sha256","operations"}
    allowed_images={image_id}
    if job=="02-ir-capture":
        keys.add("images")
        images={i:_image(inputs,job,i) for i in capture_images(inputs)}
        allowed_images=set(images)
        if document.get("images")!=[{"image_id":i,"image_digest":v[1],"toolchain_sha256":v[2]}
                                    for i,v in sorted(images.items())]:
            raise Blocked(f"{job}: B13 receipt image set differs from the accepted native build")
    if (set(document)!=keys or
        document.get("schema")!="appsec-review/ir-b13-receipts/1.0" or document.get("run_id")!=inputs["run_id"] or
        document.get("job_id")!=job or document.get("image_id")!=image_id or
        document.get("image_digest")!=image_digest or document.get("toolchain_sha256")!=toolchain_sha or
        not isinstance(document.get("operations"),list) or not document["operations"]):
        raise Blocked(f"{job}: B13 receipt manifest is invalid")
    expected_operation = {"02-ir-capture":"compile", "02-ir-link":"link",
                          "02-ir-facts":"disassemble"}[job]
    if any(not isinstance(item, dict) or item.get("operation") != expected_operation
           for item in document["operations"]):
        raise Blocked(f"{job}: B13 receipt names an unexpected operation")
    expected_count = 1
    if job == "02-ir-capture":
        result = read_json(attempt / "ir-capture.json")
        expected_count = len(result["modules"]) + sum(
            item.get("reason") == "bitcode-capture-failed" for item in result["coverage_gaps"])
    if len(document["operations"]) != expected_count:
        raise Blocked(f"{job}: B13 receipt count differs from executed tool operations")
    runtime=_runtime(inputs["source_snapshot_sha256"])
    expected_output = {"compile":"scratch/module.bc", "link":"scratch/linked.bc",
                       "disassemble":"scratch/module.ll"}[expected_operation]
    fields={"operation","adapter_attempt_id","trial_path","expected_result_sha256","output_path","output_sha256","execution_status"}
    for ordinal, record in enumerate(document["operations"], start=1):
        # A memoised operation (brief N) names the earlier attempt that ran its trial; it is
        # re-verified there, and its trial path is that attempt's own tool trial.
        owned = "owner_attempt_id" in record
        if set(record) != (fields | {"owner_attempt_id"} if owned else fields):
            raise Blocked(f"{job}: B13 operation receipt shape is invalid")
        pure=PurePosixPath(record["trial_path"])
        if (pure.is_absolute() or any(part in ("",".","..") for part in pure.parts) or
                (not owned and record["trial_path"] != f"tools/{ordinal:04d}-{expected_operation}") or
                (owned and (record["execution_status"] != "OK" or
                            not re.fullmatch(r"tools/[0-9]{4}-" + expected_operation, record["trial_path"]))) or
                record["output_path"] != expected_output):
            raise Blocked(f"{job}: B13 trial path is unsafe")
        try:
            owner = (beneath(attempt.parent, attempt.parent / identifier(record["owner_attempt_id"]))
                     if owned else attempt)
        except ValueError as exc:
            raise Blocked(f"{job}: B13 receipt owner attempt is invalid") from exc
        if owned and (owner == attempt or not owner.is_dir()):
            raise Blocked(f"{job}: B13 receipt owner attempt is absent")
        trial=owner.joinpath(*pure.parts); request=read_json(trial/"logs/container"/ce.REQUEST_FILE)
        if (request.get("image") or {}).get("image_id") not in allowed_images:
            raise Blocked(f"{job}: B13 operation ran on an image outside the accepted build images")
        errors=ce.verify_container_result(trial,run_id=inputs["run_id"],job_id=job,
            attempt_id=record["adapter_attempt_id"],request=request,images_dir=runtime.images_dir,
            expected_result_sha256=record["expected_result_sha256"],**_host(runtime))
        output=trial.joinpath(*PurePosixPath(record["output_path"]).parts)
        actual="sha256:"+file_hash(output) if output.is_file() and not output.is_symlink() else None
        terminal = read_json(trial / "logs/container" / ce.RESULT_FILE)
        if (errors or actual!=record["output_sha256"] or
                terminal.get("execution_status") != record["execution_status"] or
                (job != "02-ir-capture" and record["execution_status"] != "OK")):
            raise Blocked(f"{job}: B13 operation receipt failed re-verification")
