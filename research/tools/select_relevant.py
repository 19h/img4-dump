"""Run inside IDA after collect_inventory.py; set AUDIT_ROOT to change output."""
import os,json,re,ida_nalt,idautils,ida_funcs,ida_name
base=os.path.basename(ida_nalt.get_input_file_path())
root=os.path.join(globals().get("AUDIT_ROOT", "/Users/int/dev/img4-dump/research/ida"), "")
d=json.load(open(root+base+".inventory.json"))
rx=re.compile(r"img4|im4[pmrc]|image4|(?:^|_)DER|asn1|manifest|kbag|payload|payp|nonce|lzss|lzfse|compress|personaliz|ticket|digest|fourcc|fingerprint|trustcache",re.I)
functions={f["ea"]:f for f in d["functions"]}
selected={f["ea"]:{"function":f,"reasons":["symbol"],"anchors":[]} for f in d["functions"] if rx.search(f["name"]) and ".cold." not in f["name"]}
for s in d["strings"]:
 if rx.search(s["text"]) or re.fullmatch(r"[A-Za-z0-9]{4}",s["text"]):
  for x in idautils.XrefsTo(int(s["ea"],16),0):
   f=ida_funcs.get_func(x.frm)
   if f and hex(f.start_ea) in functions:
    k=hex(f.start_ea)
    v=selected.setdefault(k,{"function":functions[k],"reasons":["string"],"anchors":[]})
    v["anchors"].append({"ref_ea":hex(x.frm),"string_ea":s["ea"],"text":s["text"]})
for depth in range(2):
 for k in list(selected):
  for x in idautils.CodeRefsTo(int(k,16),0):
   f=ida_funcs.get_func(x)
   if f and hex(f.start_ea) in functions and ".cold." not in functions[hex(f.start_ea)]["name"]:
    ea=hex(f.start_ea)
    v=selected.setdefault(ea,{"function":functions[ea],"reasons":["caller"],"anchors":[]})
    a={"ref_ea":hex(x),"callee":k}
    if a not in v["anchors"]: v["anchors"].append(a)
out={"binary":base,"sha256":d["sha256"],"criteria":rx.pattern,"caller_depth":2,"selected":list(selected.values())}
with open(root+base+".relevance.json","w") as f: json.dump(out,f,indent=2)
print(json.dumps({"binary":base,"selected":len(selected),"functions":d["function_count"]}))
