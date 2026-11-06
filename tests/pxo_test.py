#!/usr/bin/env python3
"""open_project pre-scan tests against a RUNNING hardened bridge.
  python3 tests/pxo_test.py WRITE_DIR
Saves a real project via the bridge, then crafts hostile variants (3D scene with an embedded script,
object literal in image_size, legacy non-zip, wrong extension) and requires every one to be refused
while the genuine file opens. Payload scenes only print; nothing is executed by this script."""
import http.client
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

W = Path(sys.argv[1])
TOKEN = (Path.home() / ".pixelorama-mcp" / "token").read_text().strip()
results = []


def call(tool, params):
    c = http.client.HTTPConnection("127.0.0.1", 7373, timeout=30)
    c.request("POST", "/command", json.dumps({"tool": tool, "params": params}),
              {"Host": "127.0.0.1:7373", "Content-Type": "application/json", "X-Pix-Mcp-Token": TOKEN})
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def rewrite(src: Path, dst: Path, mutate):
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "data.json":
                data = json.dumps(mutate(json.loads(data))).encode()
            zout.writestr(item, data)
    return dst


good = W / "pxo_good.pxo"
call("create_canvas", {"width": 8, "height": 8, "name": "pxo_probe"})
call("draw_pixel", {"x": 1, "y": 1, "color": "#aa3300"})
st, js = call("save_project", {"path": str(good)})
check("save_project writes a genuine .pxo", st == 200 and good.exists(), js.get("error"))
data = json.loads(zipfile.ZipFile(good).read("data.json"))
sizes = [c.get("image_size") for f in data.get("frames", []) for c in f.get("cels", []) if "image_size" in c]
check("genuine image_size values look like '(w, h)'", all(isinstance(s, str) for s in sizes), sizes[:3])
st, js = call("open_project", {"path": str(good)})
check("genuine .pxo opens", st == 200 and js.get("success"), js.get("error"))

scene = W / "pxo_scene.pxo"
shutil.copy(good, scene)
with zipfile.ZipFile(scene, "a") as z:
    z.writestr("scene/0", '[gd_scene format=3]\n[sub_resource type="GDScript" id="s"]\n'
                          'script/source = "extends Node3D\\nfunc _ready(): print(\\"pxo payload\\")"\n'
                          '[node name="Root" type="Node3D"]\nscript = SubResource("s")\n')
st, js = call("open_project", {"path": str(scene)})
check("3D scene entry refused", st == 400 and "scene" in (js.get("error") or ""), js.get("error"))


def obj(d):
    for f in d.get("frames", []):
        for c in f.get("cels", []):
            c["image_size"] = 'Object(Node,"script":null)'
    return d


bad_obj = rewrite(good, W / "pxo_obj.pxo", obj)
st, js = call("open_project", {"path": str(bad_obj)})
check("object literal in image_size refused", st == 400 and "image_size" in (js.get("error") or ""), js.get("error"))


def nested(d):
    d["user_data"] = {"x": ['Object(Resource,"resource_path":"")']}
    return d


bad_nested = rewrite(good, W / "pxo_nested.pxo", nested)
st, js = call("open_project", {"path": str(bad_nested)})
check("object literal anywhere in data.json refused", st == 400 and "object" in (js.get("error") or "").lower(), js.get("error"))

legacy = W / "pxo_legacy.pxo"
legacy.write_bytes(b"not a zip, legacy v0 layout")
st, js = call("open_project", {"path": str(legacy)})
check("legacy non-zip .pxo refused", st == 400 and "zip" in (js.get("error") or ""), js.get("error"))

tres = W / "pxo_res.tres"
tres.write_text('[gd_resource type="Resource" format=3]\n[resource]\n')
st, js = call("open_project", {"path": str(tres)})
check("non-.pxo extension refused", st == 400 and ".pxo" in (js.get("error") or ""), js.get("error"))

for f in (good, scene, bad_obj, bad_nested, legacy, tres):
    try:
        os.unlink(f)
    except FileNotFoundError:
        pass
failed = 0
for name, ok, detail in results:
    failed += not ok
    print(("PASS" if ok else "FAIL") + "  " + name + ("" if ok else "  <- " + str(detail)))
print(f"\n{len(results) - failed}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
