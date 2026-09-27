"""Nominal E09/E10 test execution and deterministic result/coverage ingestion cores."""
from __future__ import annotations
import json
import math
import os
from datetime import datetime, timedelta, timezone
import base64
from pathlib import Path, PurePosixPath
import re
import threading
import xml.etree.ElementTree as ET
from typing import Any
import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now as state_now, read_json, run_path
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
from worker_result import validate_worker_result
from execution_state import tree_hashes
import intake

PROHIBITED_KEYS = {"finding", "findings", "severity", "vulnerability", "vulnerabilities", "clean_claim"}
EXECUTION_JOB="02-test-execution"; RESULT_JOB="02-test-result-ingest"; COVERAGE_JOB="02-test-coverage-ingest"
CONTROL="test-execution-control.json"
PERMISSIONS={EXECUTION_JOB:["target-execution","write-run-data"],
             RESULT_JOB:["read-run-data","write-run-data"],COVERAGE_JOB:["read-run-data","write-run-data"]}

def utc_now()->str: return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sha(path: Path) -> str: return "sha256:" + file_hash(path)

def source_tree_sha256(target:Path)->str:
    records={}
    for current,dirs,files in os.walk(target.resolve(),topdown=True,followlinks=False):
        dirs[:]=sorted(name for name in dirs if name!=".git")
        for name in sorted(files):
            path=Path(current,name); relative=path.relative_to(target).as_posix()
            if path.is_symlink(): records[relative]={"kind":"symlink","target":os.readlink(path)}
            elif path.is_file(): records[relative]={"kind":"file","sha256":sha(path)}
            else: raise Blocked(f"test evidence checkout contains a special file: {relative}")
    return "sha256:"+digest(records)

def variant(native: dict, unit: dict) -> str:
    return "sha256:" + digest({"source_revision":native["source_revision"], "unit_id":unit["unit_id"],
        "image_id":unit["image_id"], "image_digest":unit["image_digest"],
        "compile_database":unit["compile_database"], "binaries":unit["binaries"]})

def permission(run_id: str, source: str, command_profile_id: str, grants: list[dict], now: str) -> dict:
    params={name:None for name in pc.PARAMETER_NAMES}; params.update(
        command_profile_id=command_profile_id, target_path=".")
    cap={"kind":"target-execution","version":"1.0","parameters":params,"origin":"registry"}
    requirement={"schema":"appsec-review/permission-requirement/1.0","job_id":"02-test-execution","capabilities":[cap]}
    # Rebind staged grants to the current source hash: intake rewrites the manifest on every re-run
    # (ADR-0013). The grant stays bound to this run and job.
    grants=[{**g,"binding":{**g["binding"],"source_snapshot_sha256":source}}
            if isinstance(g,dict) and g.get("binding",{}).get("run_id")==run_id else g for g in grants]
    context={"run_id":run_id,"job_id":"02-test-execution","source_snapshot_sha256":source,
             "now":now,"registry_ceiling":[cap]}
    decision=pc.evaluate(requirement,grants,context); pc.require_granted(
        decision,requirement=requirement,grants=grants,context=context)
    return {"requirement":requirement,"grants":grants,"decision":decision,
            "fingerprint_sha256":pc.input_fingerprint_component(decision)}

def stage_control(run_id: str, *, authority: str = "Task-authorized engagement owner") -> Path:
    """Stage the closed no-network Autotools test command against one accepted native unit."""
    _attempt,native,_lineage=accepted(run_id,"02-native-build","native-build.json",
        "native-build.schema.json","native-build")
    units=native.get("units",[])
    if len(units)!=1 or not isinstance(units[0].get("unit_id"),str):
        raise Blocked("test control staging requires exactly one accepted native build unit")
    _target_path,source,_tree,revision=target(run_id)
    if native.get("source_revision")!=revision:
        raise Blocked("test control staging requires the current accepted native build")
    issued=datetime.now(timezone.utc).replace(microsecond=0)
    profile="hello-autotools-make-check-v1"
    params={name:None for name in pc.PARAMETER_NAMES}; params.update(
        command_profile_id=profile,target_path=".")
    capability={"kind":"target-execution","version":"1.0","parameters":params,
                "origin":"staged-run-config"}
    grant={"schema":"appsec-review/permission-grant/1.0",
        "grant_id":"happy-path-02-test-execution","effect":"ALLOW",
        "authority":{"name":authority,"role":"engagement-owner"},
        "issued_at":issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at":(issued+timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "binding":{"run_id":run_id,"source_snapshot_sha256":source,"job_id":EXECUTION_JOB},
        "justification":"Run the target's bounded Autotools test target in the accepted build image.",
        "capabilities":[capability]}
    value={"schema":"appsec-review/test-execution-control/1","command_profile_id":profile,
        "unit_id":units[0]["unit_id"],"argv":["make","check"],
        "environment":[{"name":"LANG","value":"C"},{"name":"LC_ALL","value":"C"}],
        "timeout_seconds":600,"authorization_time":issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "result_format":"unsupported","result_path":None,
        "coverage_format":"none","coverage_path":None,"grants":[grant]}
    errors=validate_document(value,"test-execution-control.schema.json")
    if errors: raise Blocked("generated test execution control is invalid")
    path=data_path(run_id,"controls",CONTROL); atomic_json(path,value); return path

def execution_record(*, run_id:str, source:str, native_lineage:dict, native:dict, unit:dict,
                     argv:list[str], environment:list[dict], timeout_seconds:int,
                     permission_record:dict, exit_code:int, raw_results:dict[str,Path],
                     artifact_root:Path|None=None, checkout_identity_sha256:str|None=None,
                     source_tree_sha256_value:str|None=None,result_format:str="junit-xml", coverage_format:str="lcov") -> dict:
    if not argv or timeout_seconds < 1 or timeout_seconds > 3600: raise Blocked("bounded declared test argv is required")
    if permission_record["decision"].get("decision") != "GRANTED": raise Blocked("test execution permission denied")
    artifact_root=artifact_root or next(iter(raw_results.values()),Path(".")).parent
    artifacts=[{"kind":kind,"path":path.relative_to(artifact_root).as_posix(),"sha256":sha(path),"size_bytes":path.stat().st_size}
               for kind,path in sorted(raw_results.items())]
    status="PASS" if exit_code==0 else "FAIL"; kinds={item["kind"] for item in artifacts}; gaps=[]
    if result_format=="junit-xml" and "test-results" not in kinds: gaps.append("Declared JUnit result artifact was not published.")
    if result_format=="unsupported": gaps.append("Declared test-result format is unsupported.")
    if coverage_format=="lcov" and "coverage" not in kinds: gaps.append("Declared LCOV coverage artifact was not published.")
    if coverage_format in {"unsupported","none"}: gaps.append("No supported coverage format was declared; source coverage is unknown.")
    return {"schema":"appsec-review/test-execution/1","run_id":run_id,
      "source_snapshot_sha256":source,"source_tree_sha256":source_tree_sha256_value or checkout_identity_sha256 or source,
      "checkout_identity_sha256":checkout_identity_sha256 or source,
      "source_revision":native["source_revision"],
      "native_build":native_lineage,"unit_id":unit["unit_id"],"variant_sha256":variant(native,unit),
      "image_id":unit["image_id"],"image_digest":unit["image_digest"],
      "binary_set_sha256":"sha256:"+digest([(x["artifact_path"],x["sha256"]) for x in unit["binaries"]]),
      "command":{"argv":argv,"environment":environment,"timeout_seconds":timeout_seconds,
                 "network":"none","credentials":[],"mutation":"run-owned-copy"},
      "permission_fingerprint_sha256":permission_record["fingerprint_sha256"],
      "result_format":result_format,"coverage_format":coverage_format,
      "execution_status":status,"exit_code":exit_code,"artifacts":artifacts,
      "coverage_gaps":gaps}

def junit(execution:dict, path:Path) -> dict:
    try: root=ET.parse(path).getroot()
    except Exception as exc: raise Blocked("unsupported or malformed JUnit XML") from exc
    cases=[]; seen=set()
    for node in root.iter("testcase"):
        name=f"{node.get('classname','')}::{node.get('name','')}"
        if name in seen: raise Blocked("duplicate test identity")
        seen.add(name); outcome="failed" if node.find("failure") is not None or node.find("error") is not None else (
            "skipped" if node.find("skipped") is not None else "passed")
        try: duration=float(node.get("time","0"))
        except ValueError as exc: raise Blocked("JUnit duration is malformed") from exc
        if not math.isfinite(duration) or duration<0: raise Blocked("JUnit duration is invalid")
        cases.append({"test_id":"test_"+digest(name)[:16],"name":name,"outcome":outcome,
                      "duration_seconds":duration})
    cases.sort(key=lambda x:x["name"])
    result={"schema":"appsec-review/test-results/1","run_id":execution["run_id"],
      "execution":execution_lineage(execution),"raw_sha256":sha(path),"format":"junit-xml",
      "outcomes":cases,"counts":{key:sum(x["outcome"]==key for x in cases) for key in ("passed","failed","skipped")},
      "coverage_gaps":([] if cases else ["JUnit document contains no test cases"])}
    if validate_document(result,"test-results.schema.json"): raise Blocked("normalized test results invalid")
    return result

def lcov(execution:dict, path:Path, target:Path) -> dict:
    files=[]; current=None; seen=set()
    try: lines=path.read_text(encoding="utf-8").splitlines()
    except Exception as exc: raise Blocked("unsupported or malformed LCOV") from exc
    for line in lines:
        if line.startswith("SF:"):
            raw=line[3:]; p=Path(raw); p=(target/p) if not p.is_absolute() else p
            try: rel=p.resolve().relative_to(target.resolve()).as_posix()
            except ValueError as exc: raise Blocked("coverage source escapes target") from exc
            if rel in seen: raise Blocked("duplicate coverage source identity")
            seen.add(rel)
            if not p.is_file() or p.is_symlink(): raise Blocked("coverage source is missing")
            current={"path":rel,"source_sha256":sha(p),"lines":[],"_seen":set()}; files.append(current)
        elif line.startswith("DA:"):
            if current is None: raise Blocked("LCOV line data has no source file")
            try: number,hits=map(int,line[3:].split(",")[:2])
            except (ValueError,TypeError) as exc: raise Blocked("LCOV line data is malformed") from exc
            if number<1 or hits<0 or number in current["_seen"]: raise Blocked("LCOV line identity or hit count is invalid")
            current["_seen"].add(number); current["lines"].append({"line":number,"hits":hits})
        elif line and not (line.startswith(("TN:","end_of_record","LF:","LH:","BR"))):
            raise Blocked("unsupported LCOV record")
    for item in files: item.pop("_seen")
    files.sort(key=lambda x:x["path"])
    partial=any(line["hits"] == 0 for item in files for line in item["lines"])
    gaps=[] if files else ["LCOV contains no source-linked coverage"]
    if partial: gaps.append("Coverage is partial; one or more reported source lines were not executed.")
    result={"schema":"appsec-review/test-coverage/1","run_id":execution["run_id"],
      "execution":execution_lineage(execution),"raw_sha256":sha(path),"format":"lcov",
      "files":files,"coverage_gaps":gaps}
    if validate_document(result,"test-coverage.schema.json"): raise Blocked("normalized coverage invalid")
    return result

def execution_lineage(value:dict)->dict:
    return {key:value[key] for key in ("source_snapshot_sha256","source_tree_sha256","checkout_identity_sha256","source_revision","native_build","unit_id",
      "variant_sha256","image_id","image_digest","binary_set_sha256","permission_fingerprint_sha256")}

def _relative(root:Path,value:Any)->Path:
    if not isinstance(value,str) or not value or "\\" in value: raise Blocked("artifact path invalid")
    pure=PurePosixPath(value)
    if pure.is_absolute() or any(x in {"",".",".."} for x in pure.parts): raise Blocked("artifact path invalid")
    path=root.joinpath(*pure.parts)
    try: path.resolve().relative_to(root.resolve())
    except ValueError as exc: raise Blocked("artifact path escapes attempt") from exc
    if path.is_symlink(): raise Blocked("artifact path is a symlink")
    return path

def accepted(run_id:str,job:str,artifact:str,schema:str,contract:str)->tuple[Path,dict,dict]:
    base=data_path(run_id,"jobs",job); pp=base/"accepted.json"
    if not pp.is_file() or pp.is_symlink(): raise Blocked(f"{job}: accepted pointer required")
    pointer=read_json(pp); attempt=base/"attempts"/str(pointer.get("attempt_id","")); envelope=attempt/str(pointer.get("envelope_path",""))
    required={"schema","status","run_id","job","attempt_id","fingerprint","envelope_path","envelope_sha256","hashes","accepted_at"}
    latest=read_json(base/"latest.json") if (base/"latest.json").is_file() else {}
    if (set(pointer)!=required or pointer.get("schema")!="appsec-review/accepted-worker-result/1.0" or pointer.get("run_id")!=run_id or
        pointer.get("job")!=job or pointer.get("status") not in {"OK","OK_WITH_GAPS"} or
        pointer.get("envelope_path")!="result.json" or latest.get("attempt_id")!=pointer.get("attempt_id") or
        not attempt.is_dir() or attempt.is_symlink() or tree_hashes(attempt)!=pointer.get("hashes") or
        not envelope.is_file() or file_hash(envelope)!=pointer.get("envelope_sha256")): raise Blocked(f"{job}: stale accepted pointer")
    env=read_json(envelope)
    if (validate_worker_result(env) or env.get("attempt_id")!=pointer["attempt_id"] or env.get("job_id")!=job or
        env.get("run_id")!=run_id or env.get("input_fingerprint")!=pointer["fingerprint"] or
        env.get("execution_status")!=pointer["status"] or env.get("acceptance_status")!="CURRENT" or
        env.get("output_contract")!=contract): raise Blocked(f"{job}: invalid envelope")
    published={x["path"]:x["sha256"] for x in env["artifacts"]}
    if len(published)!=len(env["artifacts"]): raise Blocked(f"{job}: envelope repeats an artifact path")
    for rel,want in published.items():
        p=_relative(attempt,rel)
        if not p.is_file() or file_hash(p)!=want: raise Blocked(f"{job}: accepted artifact changed")
    rp=_relative(attempt,artifact)
    if published.get(artifact)!=file_hash(rp): raise Blocked(f"{job}: result is not published")
    value=read_json(rp)
    if validate_document(value,schema): raise Blocked(f"{job}: result schema invalid")
    lineage={"job_id":job,"attempt_id":pointer["attempt_id"],"accepted_pointer_sha256":sha(pp),
             "envelope_sha256":sha(envelope),"result_sha256":sha(rp),"input_fingerprint":pointer["fingerprint"]}
    return attempt,value,lineage

def target(run_id:str)->tuple[Path,str,str,str]:
    manifest=run_path(run_id)/"inputs/artifact-manifest.json"; value=read_json(manifest).get("target",{}).get("repo_path") if manifest.is_file() else None
    path=Path(value) if isinstance(value,str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink(): raise Blocked("test execution target invalid")
    path=path.resolve(); identity=intake.source_identity(str(path)); tree=source_tree_sha256(path)
    return path,sha(manifest),tree,identity["revision"]

def execution_inputs(run_id:str)->dict:
    native_attempt,native,lineage=accepted(run_id,"02-native-build","native-build.json","native-build.schema.json","native-build")
    control_path=data_path(run_id,"controls",CONTROL)
    if not control_path.is_file() or validate_document(read_json(control_path),"test-execution-control.schema.json"):
        raise Blocked("explicit trusted test execution control is required")
    control=read_json(control_path); target_path,source,checkout,revision=target(run_id); inputs=read_json(native_attempt/"inputs.json")
    if ((control["result_format"]=="junit-xml" and not isinstance(control["result_path"],str)) or
            (control["coverage_format"]=="lcov" and not isinstance(control["coverage_path"],str))):
        raise Blocked("supported test evidence formats require one declared artifact path")
    if inputs.get("source_snapshot_sha256")!=source: raise Blocked("native build source generation is stale")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}",str(inputs.get("source_tree_sha256",""))):
        raise Blocked("native build inputs lack source_tree_sha256; E02 must attest the post-build checkout bytes")
    if inputs["source_tree_sha256"]!=checkout: raise Blocked("checkout bytes differ from accepted E02 source-tree attestation")
    if native.get("source_revision")!=revision: raise Blocked("native build checkout revision is stale")
    units=[x for x in native["units"] if x["unit_id"]==control["unit_id"]]
    if len(units)!=1: raise Blocked("declared test unit does not resolve uniquely")
    unit=units[0]
    for record in [unit["compile_database"],*unit["binaries"]]:
        candidate=_relative(native_attempt,record.get("path",record.get("artifact_path")))
        if not candidate.is_file() or sha(candidate)!=record["sha256"]: raise Blocked("accepted native artifact changed")
    image_record=inputs.get("image_records",{}).get(unit["image_id"])
    if (not isinstance(image_record,dict) or image_record.get("value",{}).get("digest")!=unit["image_digest"] or
        validate_document(image_record.get("value",{}),"container-image.schema.json")):
        raise Blocked("accepted native image record is missing or mismatched")
    grant=permission(run_id,source,control["command_profile_id"],control["grants"],control["authorization_time"])
    detail={"run_id":run_id,"job":EXECUTION_JOB,"source_snapshot_sha256":source,"target_path":str(target_path),
      "source_tree_sha256":checkout,"checkout_identity_sha256":checkout,"source_revision":revision,
      "native_attempt_path":str(native_attempt),"native":native,"native_lineage":lineage,"unit":unit,
      "image_record":image_record,
      "control":control,"control_sha256":sha(control_path),
      "permission_fingerprint_sha256":grant["fingerprint_sha256"],"boundary_sha256":ce.boundary_sha256()}
    detail["build_lineage_sha256"]="sha256:"+digest({"job":EXECUTION_JOB,"source_snapshot_sha256":source,"upstream":lineage})
    return detail

RUNNER=r'''import json,pathlib,shutil,subprocess,sys
cfg=json.loads(sys.argv[1]); work=pathlib.Path('/scratch/workspace'); shutil.copytree('/workspace',work,symlinks=True)
p=subprocess.run(cfg['argv'],cwd=work,env={**__import__('os').environ,**{x['name']:x['value'] for x in cfg['environment']}},check=False)
for key,name in (('result_path','test-results.xml'),('coverage_path','coverage.info')):
 src=work/cfg.get(key,'') if cfg.get(key) else None
 if src and src.is_file(): shutil.copyfile(src,pathlib.Path('/scratch')/name)
pathlib.Path('/scratch/execution.json').write_text(json.dumps({'exit_code':p.returncode},sort_keys=True)+'\n')
sys.exit(0)'''

def request(run_id:str,attempt_id:str,inputs:dict)->dict:
    c=inputs["control"]; encoded=base64.b64encode(RUNNER.encode()).decode(); trusted="import base64;exec(base64.b64decode('"+encoded+"'))"
    for key in ("result_path","coverage_path"):
        value=c[key]
        if value is not None:
            pure=PurePosixPath(value)
            if not value or "\\" in value or pure.is_absolute() or any(part in {"",".",".."} for part in pure.parts):
                raise Blocked(f"test control {key} is not a normalized relative path")
    cfg={key:c[key] for key in ("argv","environment","result_path","coverage_path")}
    permit=permission(run_id,inputs["source_snapshot_sha256"],c["command_profile_id"],c["grants"],c["authorization_time"])
    return {"schema":ce.REQUEST_ID,"run_id":run_id,"job_id":EXECUTION_JOB,"attempt_id":attempt_id,
      "image":{"image_id":inputs["unit"]["image_id"],"digest":inputs["unit"]["image_digest"]},
      "argv":["/usr/bin/python3","-c",trusted,json.dumps(cfg,sort_keys=True)],"environment":c["environment"],
      "target_mounts":[{"host_path":inputs["target_path"],"container_path":"/workspace"},
                       {"host_path":inputs["native_attempt_path"],"container_path":"/inputs/native-build"}],
      "scratch_path":"scratch","log_path":"logs/container","network":{"mode":"none","destinations":[]},
      "permission":{k:permit[k] for k in ("requirement","grants","decision")},
      "limits":{"timeout_seconds":c["timeout_seconds"],"memory_bytes":2147483648,"cpu_millis":2000,
                "pids":256,"tmpfs_bytes":268435456,"stdout_limit_bytes":1048576,"stderr_limit_bytes":1048576}}

def runtime(source:str, command_profile_id:str, images_dir:Path)->ce.ContainerRuntime:
    d=ce.host_defaults()
    if d["docker_executable"] is None: raise Blocked("Docker unavailable")
    return ce.ContainerRuntime(docker_executable=d["docker_executable"],docker_host=None,images_dir=images_dir,
      host_flavor=d["host_flavor"],container_user=d["container_user"],source_snapshot_sha256=source,
      registry_ceiling=inputs_ceiling(command_profile_id),
      clock=utc_now,cancel=threading.Event())

def inputs_ceiling(command_profile_id:str)->list[dict]:
    params={name:None for name in pc.PARAMETER_NAMES}; params.update(command_profile_id=command_profile_id,target_path=".")
    return [{"kind":"target-execution","version":"1.0","parameters":params,"origin":"registry"}]

SPECS={EXECUTION_JOB:("test-execution.json","test-execution.schema.json","test-execution"),
       RESULT_JOB:("test-results.json","test-results.schema.json","test-result-intelligence"),
       COVERAGE_JOB:("test-coverage.json","test-coverage.schema.json","test-coverage-intelligence")}

def code_hashes(job:str)->dict[str,str]:
    wrapper={EXECUTION_JOB:"test_execution.py",RESULT_JOB:"test_result_ingest.py",COVERAGE_JOB:"test_coverage_ingest.py"}[job]
    names=("test_evidence.py",wrapper,"container_execution.py","permission_capabilities.py",
           "publish_job_output.py",f"registry/output-contracts/{SPECS[job][2]}.json",
           f"registry/job-templates/{job}.json","registry/roles/test-evidence-producer.json",
           "registry/tooling-profiles/bounded-test-evidence.json")
    result={name:file_hash(ROOT/name) for name in names}
    schemas=[SPECS[job][1],"test-execution-lineage.schema.json","test-native-build-lineage.schema.json"]
    if job==EXECUTION_JOB: schemas += ["test-execution-control.schema.json","native-build.schema.json",
                                      "pinned-container-result.schema.json"]
    else: schemas += ["test-execution.schema.json"]
    result.update({"schemas/"+name:file_hash(ROOT.parent/"schemas"/name) for name in schemas})
    return result

def ingest_inputs(run_id:str,job:str)->dict:
    attempt,execution,lineage=accepted(run_id,EXECUTION_JOB,"test-execution.json","test-execution.schema.json","test-execution")
    target_path,source,checkout,revision=target(run_id)
    if execution["source_snapshot_sha256"]!=source: raise Blocked("test execution source generation is stale")
    if execution["source_tree_sha256"]!=checkout:
        raise Blocked("test execution source-tree attestation is stale")
    if execution["checkout_identity_sha256"]!=checkout or execution["source_revision"]!=revision:
        raise Blocked("test execution checkout identity is stale")
    kind="test-results" if job==RESULT_JOB else "coverage"
    records=[x for x in execution["artifacts"] if x["kind"]==kind]
    if len(records)>1: raise Blocked(f"duplicate raw {kind} artifacts")
    raw=None
    if records:
        raw=_relative(attempt,records[0]["path"])
        if not raw.is_file() or sha(raw)!=records[0]["sha256"]: raise Blocked(f"raw {kind} artifact changed")
    return {"run_id":run_id,"job":job,"execution":execution,"execution_lineage":lineage,
            "execution_attempt_path":str(attempt),"raw_path":str(raw) if raw else None,
            "raw_kind":kind,"target_path":str(target_path),
            "source_snapshot_sha256":source,"source_tree_sha256":checkout,
            "checkout_identity_sha256":checkout,"source_revision":revision,
            "build_lineage_sha256":"sha256:"+digest({"job":job,"source_snapshot_sha256":source,"upstream":lineage}),
            "code":code_hashes(job)}

def current_inputs(run_id:str,job:str)->dict:
    value=execution_inputs(run_id) if job==EXECUTION_JOB else ingest_inputs(run_id,job)
    value["code"]=code_hashes(job); return value

def producer_receipts(run_id:str,job:str,inputs:dict)->tuple[dict,dict]:
    permission_receipt={"schema":"appsec-review/producer-permission-receipt/1.0","run_id":run_id,
      "job_id":job,"source_snapshot_sha256":inputs["source_snapshot_sha256"],"permissions":PERMISSIONS[job]}
    lineage_receipt={"schema":"appsec-review/producer-lineage-receipt/1.0","run_id":run_id,
      "job_id":job,"source_snapshot_sha256":inputs["source_snapshot_sha256"],
      "build_lineage_sha256":inputs["build_lineage_sha256"]}
    return permission_receipt,lineage_receipt

def _host(rt:ce.ContainerRuntime)->dict:
    return {"host_flavor":rt.host_flavor,"docker_host":rt.docker_host,"docker_executable":rt.docker_executable,
            "container_user":rt.container_user}

def derive_ingest(inputs:dict,job:str)->dict:
    execution=inputs["execution"]; raw=Path(inputs["raw_path"]) if inputs["raw_path"] else None
    if job==RESULT_JOB:
        if raw is None or execution["result_format"]!="junit-xml":
            return {"schema":"appsec-review/test-results/1","run_id":execution["run_id"],
              "execution":execution_lineage(execution),"raw_sha256":sha(raw) if raw else None,"format":"unsupported",
              "outcomes":[],"counts":{"passed":0,"failed":0,"skipped":0},
              "coverage_gaps":["No supported JUnit test-result artifact was published."]}
        return junit(execution,raw)
    if raw is None or execution["coverage_format"]!="lcov":
        return {"schema":"appsec-review/test-coverage/1","run_id":execution["run_id"],
          "execution":execution_lineage(execution),"raw_sha256":sha(raw) if raw else None,
          "format":"unsupported" if raw or execution["coverage_format"]=="unsupported" else "none","files":[],
          "coverage_gaps":["No coverage artifact was published; source coverage is unknown."]}
    return lcov(execution,raw,Path(inputs["target_path"]))

def validate_attempt(run_id:str,job:str,attempt:Path,inputs:dict)->None:
    if read_json(attempt/"inputs.json")!=inputs: raise Blocked(f"{job}: immutable inputs changed")
    if current_inputs(run_id,job)!=inputs: raise Blocked(f"{job}: accepted upstream, source, control, or implementation changed")
    result=read_json(attempt/SPECS[job][0])
    if validate_document(result,SPECS[job][1]): raise Blocked(f"{job}: result schema invalid")
    def prohibited(value:Any)->bool:
        if isinstance(value,dict):
            return any(str(key).lower() in PROHIBITED_KEYS or prohibited(item) for key,item in value.items())
        if isinstance(value,list): return any(prohibited(item) for item in value)
        return False
    if prohibited(result): raise Blocked(f"{job}: prohibited finding/clean promotion")
    if (read_json(attempt/"permission.json"),read_json(attempt/"lineage.json"))!=producer_receipts(run_id,job,inputs):
        raise Blocked(f"{job}: F02 permission/lineage receipts changed")
    if job==EXECUTION_JOB:
        receipt=read_json(attempt/"b13-receipt.json"); trial=attempt/receipt["trial_path"]
        req=read_json(trial/"logs/container"/ce.REQUEST_FILE); registry=attempt/receipt["registry_path"]
        rt=runtime(inputs["source_snapshot_sha256"],inputs["control"]["command_profile_id"],registry)
        errors=ce.verify_container_result(trial,run_id=run_id,job_id=job,attempt_id=receipt["adapter_attempt_id"],
          request=req,images_dir=rt.images_dir,expected_result_sha256=receipt["expected_result_sha256"],**_host(rt))
        if errors: raise Blocked(f"{job}: B13 evidence invalid")
        for item in result["artifacts"]:
            p=_relative(attempt,item["path"])
            if not p.is_file() or sha(p)!=item["sha256"]: raise Blocked(f"{job}: raw artifact changed")
        inner=read_json(trial/"scratch/execution.json"); raw={}
        if (trial/"scratch/test-results.xml").is_file(): raw["test-results"]=trial/"scratch/test-results.xml"
        if (trial/"scratch/coverage.info").is_file(): raw["coverage"]=trial/"scratch/coverage.info"
        permit=permission(run_id,inputs["source_snapshot_sha256"],inputs["control"]["command_profile_id"],
                          inputs["control"]["grants"],req["permission"]["decision"]["evaluated_at"])
        expected=execution_record(run_id=run_id,source=inputs["source_snapshot_sha256"],
          native_lineage=inputs["native_lineage"],native=inputs["native"],unit=inputs["unit"],
          argv=inputs["control"]["argv"],environment=inputs["control"]["environment"],
          timeout_seconds=inputs["control"]["timeout_seconds"],permission_record=permit,exit_code=inner["exit_code"],
          raw_results=raw,artifact_root=attempt,source_tree_sha256_value=inputs["source_tree_sha256"],
          checkout_identity_sha256=inputs["checkout_identity_sha256"],result_format=inputs["control"]["result_format"],
          coverage_format=inputs["control"]["coverage_format"])
        if result!=expected: raise Blocked(f"{job}: execution evidence differs from immutable inputs and B13 result")
    elif result!=derive_ingest(inputs,job): raise Blocked(f"{job}: normalized evidence is stale")

def run_job(run_id:str,dagster_id:str,job:str,force:bool=False)->dict:
    base=data_path(run_id,"jobs",job); result_name,_schema,contract=SPECS[job]
    def execute(allocation,inputs,fingerprint):
        attempt=allocation["attempt"]
        if current_inputs(run_id,job)!=inputs: raise Blocked(f"{job}: inputs changed before execution")
        if job==EXECUTION_JOB:
            adapter="test-"+allocation["attempt_id"][:12]; trial=attempt/"tools"/"declared-test"; trial.mkdir(parents=True)
            registry=attempt/"image-registry"; registry.mkdir()
            atomic_json(registry/f'{inputs["unit"]["image_id"]}.json',inputs["image_record"]["value"])
            rt=runtime(inputs["source_snapshot_sha256"],inputs["control"]["command_profile_id"],registry); req=request(run_id,adapter,inputs)
            terminal=ce.run_container(rt,run_id=run_id,job_id=job,attempt_id=adapter,attempt_root=trial,request=req)
            expected=terminal["result_sha256"]; ce.load_verified_result(trial,run_id=run_id,job_id=job,attempt_id=adapter,
              request=req,images_dir=rt.images_dir,expected_result_sha256=expected,**_host(rt))
            if terminal["execution_status"]!="OK": raise RuntimeError(f"test boundary ended {terminal['execution_status']}")
            inner=read_json(trial/"scratch/execution.json"); raw={}
            if (trial/"scratch/test-results.xml").is_file(): raw["test-results"]=trial/"scratch/test-results.xml"
            if (trial/"scratch/coverage.info").is_file(): raw["coverage"]=trial/"scratch/coverage.info"
            permit=permission(run_id,inputs["source_snapshot_sha256"],inputs["control"]["command_profile_id"],
                              inputs["control"]["grants"],req["permission"]["decision"]["evaluated_at"])
            result=execution_record(run_id=run_id,source=inputs["source_snapshot_sha256"],native_lineage=inputs["native_lineage"],
              native=inputs["native"],unit=inputs["unit"],argv=inputs["control"]["argv"],environment=inputs["control"]["environment"],
              timeout_seconds=inputs["control"]["timeout_seconds"],permission_record=permit,exit_code=inner["exit_code"],
              raw_results=raw,artifact_root=attempt,checkout_identity_sha256=inputs["checkout_identity_sha256"],
              source_tree_sha256_value=inputs["source_tree_sha256"],
              result_format=inputs["control"]["result_format"],coverage_format=inputs["control"]["coverage_format"])
            atomic_json(attempt/"b13-receipt.json",{"adapter_attempt_id":adapter,"trial_path":trial.relative_to(attempt).as_posix(),
                                                   "registry_path":registry.relative_to(attempt).as_posix(),"expected_result_sha256":expected})
            extra=["b13-receipt.json",*[x["path"] for x in result["artifacts"]]]
        else:
            result=derive_ingest(inputs,job); extra=[]
        atomic_json(attempt/result_name,result)
        permission_receipt,lineage_receipt=producer_receipts(run_id,job,inputs)
        atomic_json(attempt/"permission.json",permission_receipt); atomic_json(attempt/"lineage.json",lineage_receipt)
        status={"process":job,"status":"OK_WITH_GAPS" if result["coverage_gaps"] else "OK","run_id":run_id,
                "dagster_run_id":dagster_id,"attempt_id":allocation["attempt_id"],"qualification":"implemented_not_qualified",
                "records":len(result.get("outcomes",result.get("files",result.get("artifacts",[])))),"ended_at":state_now()}
        atomic_json(attempt/"status.json",status); (attempt/f"{contract}-summary.md").write_text(
            f"# {job}\n\n- Evidence status: {status['status']}\n- Gaps: {len(result['coverage_gaps'])}\n",encoding="utf-8")
        artifacts=[result_name,"status.json",f"{contract}-summary.md","permission.json","lineage.json",*extra]
        return record_terminal_current(base,attempt,run_id=run_id,job_id=job,dagster_run_id=dagster_id,
          worker_kind="pinned_container" if job==EXECUTION_JOB else "deterministic_python",output_contract=contract,
          input_fingerprint=fingerprint,started_at=allocation["started_at"],execution_status=status["status"],
          summary=f"Published {job} evidence.",status_record=status,artifact_paths=artifacts,gaps=result["coverage_gaps"],
          pre_envelope_validate=lambda path,_status:validate_attempt(run_id,job,path,inputs))
    return coordinate_worker_lifecycle(base,run_id=run_id,job_id=job,dagster_run_id=dagster_id,
      worker_kind="pinned_container" if job==EXECUTION_JOB else "deterministic_python",output_contract=contract,
      resume_command=f"integration required for {job}",derive_inputs=lambda:current_inputs(run_id,job),
      fingerprint_inputs=lambda x:"sha256:"+digest(x),execute_attempt=execute,
      preflight_failure_inputs=lambda exc:{"run_id":run_id,"job":job,"preflight_error":f"{type(exc).__name__}: {exc}","code":code_hashes(job)},
      force=force,post_validate=lambda attempt,_env,record:validate_attempt(run_id,job,attempt,record),
      blocked_summary=f"{job} preflight blocked.",failed_summary=f"{job} did not publish.")

def validate_job(run_id:str,job:str,pointer:dict|None=None)->Path:
    base=data_path(run_id,"jobs",job); inputs=current_inputs(run_id,job); pointer=pointer or read_json(base/"accepted.json")
    attempt,_=validate_published(base,pointer,"sha256:"+digest(inputs),expected_run_id=run_id,expected_job_id=job)
    validate_attempt(run_id,job,attempt,inputs); return attempt

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument("command",choices=["stage-control","validate"])
    parser.add_argument("run_id"); parser.add_argument("--job",default=EXECUTION_JOB,choices=sorted(SPECS))
    args=parser.parse_args()
    print(stage_control(args.run_id) if args.command=="stage-control" else validate_job(args.run_id,args.job))
