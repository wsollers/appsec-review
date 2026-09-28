"""Pinned offline adapters for Go, Java and PHP source-SAST tools."""
from __future__ import annotations
import hashlib, json
from pathlib import Path, PurePosixPath
from typing import Any
import xml.etree.ElementTree as ET

from execution_state import ROOT, file_hash

TOOL_METADATA_ROOT = ROOT.parent / "images"
TOOL_IMAGES = {"gosec":"tool-gosec","spotbugs":"tool-spotbugs","phpstan":"tool-phpstan",
               "psalm":"tool-psalm","phpcs":"tool-phpcs"}
LANGUAGES = {"gosec":"go","spotbugs":"java","phpstan":"php","psalm":"php","phpcs":"php"}
OUTPUTS = {"gosec":"scratch/gosec.json","spotbugs":"scratch/spotbugs.xml","phpstan":"logs/container/stdout.log",
           "psalm":"scratch/psalm.json","phpcs":"scratch/phpcs.json"}
PSALM_CONFIG_CONTAINER = "/inputs/source-sast-php/psalm.xml"
HIT_EXIT_CODES = {"gosec":[],"spotbugs":[],"phpstan":[1],"psalm":[2],"phpcs":[1,2]}
SUFFIXES={".go":"go",".java":"java",".php":"php"}

def _metadata(tool_id:str)->tuple[dict[str,Any],str]:
 path=TOOL_METADATA_ROOT/TOOL_IMAGES[tool_id]/"tool.json"
 try: value=json.loads(path.read_text())
 except (OSError,json.JSONDecodeError) as exc: raise ValueError(f"{tool_id} authenticated tool metadata is unavailable") from exc
 keys=("image_id","tool","version","executable","version_argv","smoke")
 if (any(key not in value for key in keys) or value["image_id"]!=TOOL_IMAGES[tool_id] or value["tool"]!=tool_id or
     not isinstance(value["version"],str) or not value["version"] or not isinstance(value["executable"],str) or
     value["version_argv"][0]!=value["executable"]): raise ValueError(f"{tool_id} tool metadata is invalid")
 return value,"sha256:"+file_hash(path)

def _argv(tool_id:str, executable:str)->list[str]:
 if tool_id=="gosec": return [executable,"-fmt","json","-out","/scratch/gosec.json","-no-fail","/workspace/..."]
 if tool_id=="spotbugs": return [executable,"-textui","-effort:min","-xml:withMessages","-output","/scratch/spotbugs.xml","/workspace"]
 if tool_id=="phpstan": return [executable,"analyse","--no-progress","--no-interaction","--level","5","--error-format","json","--memory-limit","1G","/workspace"]
 if tool_id=="psalm": return [executable,"--config="+PSALM_CONFIG_CONTAINER,"--no-cache","--no-progress","--threads=1","--report=/scratch/psalm.json","/workspace"]
 if tool_id=="phpcs": return [executable,"--report=json","--report-file=/scratch/phpcs.json","/workspace"]
 raise ValueError("unknown language SAST tool")

def detected_languages(paths:list[str])->list[str]:
 return sorted({language for path in paths for suffix,language in SUFFIXES.items() if path.lower().endswith(suffix)})

def build_plan(languages:list[str], registry:dict[str,dict[str,Any]])->list[dict[str,Any]]:
 if len(languages)!=len(set(languages)) or any(x not in set(SUFFIXES.values()) for x in languages): raise ValueError("source SAST language selection is invalid")
 plan=[]
 for tool_id,image_id in sorted(TOOL_IMAGES.items()):
  if LANGUAGES[tool_id] not in languages: continue
  metadata,metadata_sha256=_metadata(tool_id); image=registry.get(image_id)
  image_digest=image.get("digest") if isinstance(image,dict) else None
  ready=(isinstance(image_digest,str) and image_digest.startswith("sha256:") and len(image_digest)==71 and
         image.get("image_id")==metadata["image_id"])
  plan.append({"language":LANGUAGES[tool_id],"tool_id":tool_id,"version":metadata["version"],"image_id":image_id,
    "image_digest":image_digest if ready else None,"tool_metadata_sha256":metadata_sha256,
    "status":"READY" if ready else "UNAVAILABLE","executed":False,"network":{"mode":"none","destinations":[]},
    "target_read_only":True,"argv":_argv(tool_id,metadata["executable"]) if ready else [],
    "version_argv":list(metadata["version_argv"]) if ready else [],"output":OUTPUTS[tool_id] if ready else None,
    "hit_exit_codes":list(HIT_EXIT_CODES[tool_id]) if ready else [],
    "gap":None if ready else f"{LANGUAGES[tool_id]} SAST unavailable: authenticated pinned image {image_id} is absent or invalid."})
 return plan

def execution_gaps(plan:list[dict[str,Any]], executed:set[str]|None=None)->list[str]:
 executed=executed or set(); gaps=[]
 for item in plan:
  if item["status"]=="UNAVAILABLE": gaps.append(item["gap"])
  elif item["tool_id"] not in executed: gaps.append(f"{item['language']} SAST tool {item['tool_id']} has no accepted offline B13 receipt.")
 return gaps

def accepted_terminal(plan:dict[str,Any], terminal:dict[str,Any])->bool:
 if terminal.get("execution_status")=="OK" and terminal.get("exit_code")==0: return True
 return (terminal.get("cause")=="CONTAINER_EXIT_NONZERO" and terminal.get("execution_status")=="FAILED" and terminal.get("exit_code") in plan.get("hit_exit_codes",[]))

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
 relative,source=_source(path,target); data=source.read_bytes(); lines=data.count(b"\n")+(1 if data and not data.endswith(b"\n") else 0)
 if line>lines: raise ValueError("language SAST line is beyond source")
 base={"tool_id":tool,"rule_id":rule[:256],"path":relative,"start_line":line,"end_line":line,"source_sha256":"sha256:"+hashlib.sha256(data).hexdigest(),"category":"language-security-static-analysis"}
 return {"lead_id":"lead_"+hashlib.sha256(json.dumps(base,sort_keys=True).encode()).hexdigest()[:16],**base}

def _line(value)->int:
 """Tools report a line as 12, "12" or a range "38-42" (gosec); the first line is the lead."""
 text=str(value if value is not None else "0").strip()
 head=text.split("-",1)[0].strip() if text[:1]!="-" else text
 return int(head or "0")


def normalize(tool_id:str, content:bytes, target:Path)->list[dict[str,Any]]:
 if tool_id not in TOOL_IMAGES: raise ValueError("unknown language SAST tool")
 try:
  if tool_id=="spotbugs":
   root=ET.fromstring(content); rows=[]
   for bug in root.findall(".//BugInstance"):
    loc=bug.find("SourceLine")
    if loc is not None: rows.append(_lead(tool_id,bug.attrib.get("type"),loc.attrib.get("sourcepath"),_line(loc.attrib.get("start","0")),target))
   return sorted(rows,key=lambda x:(x["path"],x["start_line"],x["rule_id"]))
  raw=json.loads(content)
 except (json.JSONDecodeError,ET.ParseError,ValueError,TypeError) as exc: raise ValueError("language SAST output is malformed") from exc
 rows=[]
 if tool_id=="gosec":
  for item in raw.get("Issues",[]): rows.append(_lead(tool_id,str(item.get("rule_id")),item.get("file"),_line(item.get("line","0")),target))
 elif tool_id=="phpstan":
  for path,data in raw.get("files",{}).items():
   for item in data.get("messages",[]): rows.append(_lead(tool_id,str(item.get("identifier") or "phpstan"),path,_line(item.get("line",0)),target))
 elif tool_id=="psalm":
  if not isinstance(raw,list): raise ValueError("Psalm output must be an array")
  for item in raw: rows.append(_lead(tool_id,str(item.get("type") or item.get("shortcode")),item.get("file_path") or item.get("file_name"),_line(item.get("line_from",0)),target))
 elif tool_id=="phpcs":
  for path,data in raw.get("files",{}).items():
   for item in data.get("messages",[]): rows.append(_lead(tool_id,str(item.get("source")),path,_line(item.get("line",0)),target))
 return sorted(rows,key=lambda x:(x["path"],x["start_line"],x["tool_id"],x["rule_id"]))
