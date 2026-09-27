"""Pinned offline B13 toolchain for the E04/E05 LLVM evidence workers."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import threading
from typing import Any

import container_execution as ce
from execution_state import Blocked, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json
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


def _image(inputs: dict[str, Any], job: str) -> tuple[str, str, str, dict[str, Any]]:
    if job == "02-ir-capture":
        units = inputs["upstream_result"]["units"]
        identities = {(unit["image_id"], unit["image_digest"]) for unit in units}
        bindings = {sha for _unit, sha in inputs["toolchain_bindings"] if isinstance(sha, str)}
        accepted_records = {image_id: binding for image_id, binding in inputs["toolchain_records"]}
        if len(identities) != 1 or len(bindings) != 1 or len(accepted_records) != 1:
            raise Blocked("IR capture requires one exact native-build image generation")
        image_id, image_digest = next(iter(identities)); toolchain_sha = next(iter(bindings))
    elif job == "02-ir-link":
        accepted_records = None
        upstream = inputs["upstream_result"]
        identities = {(item["image_id"], item["image_digest"]) for item in upstream["variants"]}
        bindings = {item["toolchain_sha256"] for item in upstream["modules"]}
        if len(identities) != 1 or len(bindings) != 1:
            raise Blocked("IR link requires one exact capture image generation")
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
        self.image_id, self.image_digest, self.toolchain_sha256, self.image_record = _image(inputs, job)
        self.runtime = _runtime(inputs["source_snapshot_sha256"])
        self.receipts: list[dict[str, Any]] = []
        self.target = Path(inputs["target_path"]) if job == "02-ir-capture" else None

    def _request(self, attempt_id: str, argv: list[str], mounts: list[dict[str, str]]) -> dict[str, Any]:
        return {"schema": ce.REQUEST_ID, "run_id": self.run_id, "job_id": self.job,
            "attempt_id": attempt_id, "image": {"image_id": self.image_id, "digest": self.image_digest},
            "argv": argv, "environment": [{"name":"LANG","value":"C"},
                {"name":"LC_ALL","value":"C"},{"name":"NO_COLOR","value":"1"}],
            "target_mounts": mounts, "scratch_path":"scratch", "log_path":"logs/container",
            "network":{"mode":"none","destinations":[]},
            "permission":_permission(self.run_id,self.job,self.inputs["source_snapshot_sha256"],_utc()),
            "limits":{"timeout_seconds":{"02-ir-capture":900,"02-ir-link":300,"02-ir-facts":300}[self.job],
                "memory_bytes":4*1024*1024*1024,"cpu_millis":4000,
                "pids":512,"tmpfs_bytes":512*1024*1024,"stdout_limit_bytes":8*1024*1024,
                "stderr_limit_bytes":8*1024*1024}}

    def _run(self, operation: str, argv: list[str], mounts: list[dict[str, str]], output: str | None) -> tuple[int, Path]:
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
            if raw.stat().st_size > MAX_IR_BYTES:
                raise RuntimeError("compiled bitcode exceeds the 64 MiB bound")
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
        if raw.stat().st_size > MAX_IR_BYTES: raise RuntimeError("disassembled IR exceeds the 64 MiB bound")
        return raw.read_text(encoding="utf-8")

    def publish_receipts(self) -> None:
        atomic_json(self.attempt / RECEIPT,{"schema":"appsec-review/ir-b13-receipts/1.0",
            "run_id":self.run_id,"job_id":self.job,"image_id":self.image_id,
            "image_digest":self.image_digest,"toolchain_sha256":self.toolchain_sha256,
            "operations":self.receipts})


def factory(job: str, inputs: dict[str, Any], attempt: Path) -> B13IrToolchain:
    return B13IrToolchain(job,inputs,attempt)


def validate_receipts(job: str, inputs: dict[str, Any], attempt: Path) -> None:
    document=read_json(attempt/RECEIPT)
    image_id,image_digest,toolchain_sha,_record=_image(inputs,job)
    if (set(document)!={"schema","run_id","job_id","image_id","image_digest","toolchain_sha256","operations"} or
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
    for ordinal, record in enumerate(document["operations"], start=1):
        if set(record)!={"operation","adapter_attempt_id","trial_path","expected_result_sha256","output_path","output_sha256","execution_status"}:
            raise Blocked(f"{job}: B13 operation receipt shape is invalid")
        pure=PurePosixPath(record["trial_path"])
        if (pure.is_absolute() or any(part in ("",".","..") for part in pure.parts) or
                record["trial_path"] != f"tools/{ordinal:04d}-{expected_operation}" or
                record["output_path"] != expected_output):
            raise Blocked(f"{job}: B13 trial path is unsafe")
        trial=attempt.joinpath(*pure.parts); request=read_json(trial/"logs/container"/ce.REQUEST_FILE)
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
