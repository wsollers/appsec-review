"""Pinned offline adapters for Go, Java and PHP source-SAST tools."""
from __future__ import annotations
import hashlib, json
from pathlib import Path, PurePosixPath
from typing import Any
import xml.etree.ElementTree as ET

TOOLS = {
 "gosec":{"language":"go","image_id":"tool-gosec","version":"2.22.8","output":"scratch/gosec.json","hit_exit_codes":[1],"argv":["/opt/tool/bin/gosec","-fmt=json","-out=/scratch/gosec.json","./..."]},
 "spotbugs":{"language":"java","image_id":"tool-spotbugs","version":"4.9.3","output":"scratch/spotbugs.xml","hit_exit_codes":[],"argv":["/opt/tool/bin/spotbugs","-textui","-xml:withMessages","-output","/scratch/spotbugs.xml","/workspace"]},
 "phpstan":{"language":"php","image_id":"tool-phpstan","version":"2.1.22","output":"logs/container/stdout.log","hit_exit_codes":[1],"argv":["/opt/tool/bin/phpstan","analyse","--no-progress","--error-format=json","--memory-limit=1G","/workspace"]},
 "psalm":{"language":"php","image_id":"tool-psalm","version":"6.13.1","output":"logs/container/stdout.log","hit_exit_codes":[2],"argv":["/opt/tool/bin/psalm","--no-progress","--output-format=json","/workspace"]},
 "phpcs":{"language":"php","image_id":"tool-phpcs","version":"3.13.4","output":"logs/container/stdout.log","hit_exit_codes":[1,2,3],"argv":["/opt/tool/bin/phpcs","--report=json","/workspace"]},
}
SUFFIXES={".go":"go",".java":"java",".php":"php"}

def detected_languages(paths:list[str])->list[str]:
 return sorted({language for path in paths for suffix,language in SUFFIXES.items() if path.lower().endswith(suffix)})

def build_plan(languages:list[str], registry:dict[str,dict[str,Any]])->list[dict[str,Any]]:
 if len(languages)!=len(set(languages)) or any(x not in set(SUFFIXES.values()) for x in languages): raise ValueError("source SAST language selection is invalid")
 plan=[]
 for tool_id,spec in sorted(TOOLS.items()):
  if spec["language"] not in languages: continue
  image=registry.get(spec["image_id"]); image_digest=image.get("digest") if isinstance(image,dict) else None
  ready=isinstance(image_digest,str) and image_digest.startswith("sha256:") and len(image_digest)==71
  plan.append({"language":spec["language"],"tool_id":tool_id,"version":spec["version"],"image_id":spec["image_id"],"image_digest":image_digest if ready else None,"status":"READY" if ready else "UNAVAILABLE","executed":False,"network":{"mode":"none","destinations":[]},"target_read_only":True,"argv":list(spec["argv"]) if ready else [],"output":spec["output"] if ready else None,"hit_exit_codes":list(spec["hit_exit_codes"]) if ready else [],"gap":None if ready else f"{spec['language']} SAST unavailable: pinned image {spec['image_id']} is absent or invalid."})
 return plan

def execution_gaps(plan:list[dict[str,Any]], executed:set[str]|None=None)->list[str]:
 executed=executed or set(); gaps=[]
 for item in plan:
  if item["status"]=="UNAVAILABLE": gaps.append(item["gap"])
  elif item["tool_id"] not in executed: gaps.append(f"{item['language']} SAST tool {item['tool_id']} has no accepted offline B13 receipt.")
 return gaps

def accepted_terminal(plan:dict[str,Any], terminal:dict[str,Any])->bool:
 if terminal.get("execution_status")=="OK" and terminal.get("exit_code")==0: return True
 return (terminal.get("cause")=="CONTAINER_EXIT_NONZERO" and terminal.get("execution_status")=="FAILED" and
         terminal.get("exit_code") in plan.get("hit_exit_codes",[]))

def _source(raw:Any,target:Path)->tuple[str,Path]:
 if not isinstance(raw,str) or not raw: raise ValueError("language SAST record has no source path")
 value=raw.replace("\\","/")
 for prefix in ("/workspace/","workspace/"):
  if value.startswith(prefix): value=value[len(prefix):]
 pure=PurePosixPath(value)
 if pure.is_absolute() or any(x in {"",".",".."} for x in pure.parts): raise ValueError("language SAST path escapes target")
 path=(target/Path(*pure.parts)).resolve()
 try: path.relative_to(target.resolve())
 except ValueError as exc: raise ValueError("language SAST path escapes target") from exc
 if not path.is_file() or path.is_symlink(): raise ValueError("language SAST citation is not a regular file")
 return pure.as_posix(),path

def _lead(tool:str,rule:Any,path:Any,line:Any,target:Path)->dict[str,Any]:
 if not isinstance(rule,str) or not rule or not isinstance(line,int) or isinstance(line,bool) or line<1: raise ValueError("language SAST rule or line is invalid")
 relative,source=_source(path,target); data=source.read_bytes()
 lines=data.count(b"\n")+(1 if data and not data.endswith(b"\n") else 0)
 if line>lines: raise ValueError("language SAST line is beyond source")
 base={"tool_id":tool,"rule_id":rule[:256],"path":relative,"start_line":line,"end_line":line,"source_sha256":"sha256:"+hashlib.sha256(source.read_bytes()).hexdigest(),"category":"language-security-static-analysis"}
 return {"lead_id":"lead_"+hashlib.sha256(json.dumps(base,sort_keys=True).encode()).hexdigest()[:16],**base}

def normalize(tool_id:str, content:bytes, target:Path)->list[dict[str,Any]]:
 if tool_id not in TOOLS: raise ValueError("unknown language SAST tool")
 try:
  if tool_id=="spotbugs":
   root=ET.fromstring(content); rows=[]
   for bug in root.findall(".//BugInstance"):
    loc=bug.find("SourceLine")
    if loc is not None: rows.append(_lead(tool_id,bug.attrib.get("type"),loc.attrib.get("sourcepath"),int(loc.attrib.get("start","0")),target))
   return sorted(rows,key=lambda x:(x["path"],x["start_line"],x["rule_id"]))
  raw=json.loads(content)
 except (json.JSONDecodeError,ET.ParseError,ValueError,TypeError) as exc: raise ValueError("language SAST output is malformed") from exc
 rows=[]
 if tool_id=="gosec":
  for item in raw.get("Issues",[]): rows.append(_lead(tool_id,str(item.get("rule_id")),item.get("file"),int(item.get("line","0")),target))
 elif tool_id=="phpstan":
  for path,data in raw.get("files",{}).items():
   for item in data.get("messages",[]): rows.append(_lead(tool_id,str(item.get("identifier") or "phpstan"),path,int(item.get("line",0)),target))
 elif tool_id=="psalm":
  if not isinstance(raw,list): raise ValueError("Psalm output must be an array")
  for item in raw: rows.append(_lead(tool_id,str(item.get("type") or item.get("shortcode")),item.get("file_name"),int(item.get("line_from",0)),target))
 elif tool_id=="phpcs":
  for path,data in raw.get("files",{}).items():
   for item in data.get("messages",[]): rows.append(_lead(tool_id,str(item.get("source")),path,int(item.get("line",0)),target))
 return sorted(rows,key=lambda x:(x["path"],x["start_line"],x["tool_id"],x["rule_id"]))
