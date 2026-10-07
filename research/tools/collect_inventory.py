"""Run inside each IDA database. AUDIT_ROOT selects the artifact directory.

Use macho-layouts.json from this audit; different input hashes need new layouts.
"""
import os,json,ida_nalt,idautils,ida_name,ida_funcs,ida_bytes
path=ida_nalt.get_input_file_path()
base=os.path.basename(path)
root=os.path.join(globals().get("AUDIT_ROOT", "/Users/int/dev/img4-dump/research/ida"), "")
layouts=json.load(open(root+"macho-layouts.json"))
primary=layouts[base]["primary"]
fs=[]
for sec in primary["sections"]:
 if sec["name"]=="__text":
  fs.extend({"ea":hex(ea),"name":ida_name.get_name(ea),"size":ida_funcs.get_func(ea).size(),"flags":ida_funcs.get_func(ea).flags} for ea in idautils.Functions(sec["start"],sec["end"]))
strings=[]
for sec in primary["sections"]:
 if sec["name"] not in ("__cstring","__oslogstring","__swift5_reflstr"):continue
 ea=sec["start"]
 while ea<sec["end"]:
  raw=ida_bytes.get_strlit_contents(ea,-1,0)
  if raw:
   strings.append({"ea":hex(ea),"text":raw.decode("utf8","replace"),"section":sec["name"]})
   ea+=len(raw)+1
  else:ea=ida_bytes.next_head(ea,sec["end"])
patched=[]
def on_patch(ea,fpos,original,current):
 patched.append({"ea":hex(ea),"original":original,"current":current});return 0
ida_bytes.visit_patched_bytes(primary["start"],primary["end"],on_patch)
result={"file":path,"sha256":ida_nalt.retrieve_input_file_sha256().hex(),"primary":primary,"function_count":len(fs),"functions":fs,"strings":strings,"patched_bytes_primary":patched}
out=root+base+".inventory.json"
with open(out,"w") as f: json.dump(result,f,indent=2)
print(json.dumps({"output":out,"sha256":result["sha256"],"function_count":len(fs)}))
