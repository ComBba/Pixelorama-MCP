#!/usr/bin/env python3
"""GUI open-guard test (macOS). Opens crafted files the way a person does: `open -a Pixelorama FILE`,
which (like Finder / double-click / Dock drop) starts a NEW Pixelorama process with the file on the
command line, opened by Main._ready() through OpenSave.handle_loading_file(). Each case runs in its own
fresh instance; the test waits for that instance's bridge, then checks the payload marker and which
canvases opened, and stops the instance (Monitoring.ini removed first so the extension is not
quarantined).
  python3 tests/open_guard_test.py WRITE_DIR            # expects the boot guard: every payload blocked
  python3 tests/open_guard_test.py WRITE_DIR --probe    # only report which payloads ran (no verdict)
WRITE_DIR must be an allowed write root of the bridge. Requires: no unsaved work in Pixelorama (the
running instance is stopped). Payloads are BENIGN: each inline GDScript only writes "<case>.marker"
into WRITE_DIR. Pixelorama 1.2.4 without the guard runs pxo_scene and pxo_effect_param
(reproduced 2026-11-06)."""
import http.client
import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path

W = Path(sys.argv[1]).resolve()
PROBE = "--probe" in sys.argv
APP = "/Applications/Pixelorama.app"
TOKEN = (Path.home() / ".pixelorama-mcp" / "token").read_text().strip()
EFFECT_SHADER = "res://src/Shaders/Effects/BrightnessContrast.gdshaderinc"


def call(tool, params):
    c = http.client.HTTPConnection("127.0.0.1", 7373, timeout=30)
    c.request("POST", "/command", json.dumps({"tool": tool, "params": params}),
              {"Host": "127.0.0.1:7373", "Content-Type": "application/json", "X-Pix-Mcp-Token": TOKEN})
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def marker(case):
    return W / f"{case}.marker"


def gd_source(case, base):
    """Inline GDScript (escaped for a Godot text resource) that writes the case marker in _init."""
    return (f'extends {base}\\nfunc _init():\\n\\tvar f = FileAccess.open(\\"{marker(case)}\\", '
            f'FileAccess.WRITE)\\n\\tf.store_string(\\"ran\\")\\n\\tf.close()\\n')


def evil_tres(case):
    p = W / f"{case}_payload.tres"
    p.write_text('[gd_resource type="Resource" load_steps=2 format=3]\n\n'
                 f'[sub_resource type="GDScript" id="s"]\nscript/source = "{gd_source(case, "Resource")}"\n\n'
                 '[resource]\nscript = SubResource("s")\n')
    return p


def pxo_variant(base, dst, mutate=None, extra=None):
    d = json.loads(zipfile.ZipFile(base).read("data.json"))
    if mutate:
        mutate(d)
    with zipfile.ZipFile(base) as zin, zipfile.ZipFile(dst, "w") as zout:
        for it in zin.infolist():
            data = zin.read(it.filename)
            zout.writestr(it, json.dumps(d).encode() if it.filename == "data.json" else data)
        for name, content in (extra or {}).items():
            zout.writestr(name, content)
    return dst


DATA = Path.home() / "Library/Application Support/pixelorama"
GUARD_LINE = 'PixMcpOpenGuard="*user://pix_mcp_guard/boot_guard.gd"'


def health():
    try:
        c = http.client.HTTPConnection("127.0.0.1", 7373, timeout=2)
        c.request("GET", "/health", headers={"Host": "127.0.0.1:7373"})
        return json.loads(c.getresponse().read())
    except OSError:
        return None


def canvases():
    try:
        st, js = call("list_canvases", {})
    except OSError:
        return None   # instance not up (Godot aborts on a .tres/.tscn/.res command-line argument)
    return [c.get("name") for c in js.get("data", {}).get("canvases", [])] if st == 200 else None


def pids():
    r = subprocess.run(["pgrep", "-x", "Pixelorama"], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split()]


def stop_all():
    for _ in range(3):
        (DATA / "extensions" / "Monitoring.ini").unlink(missing_ok=True)
        for pid in pids():
            subprocess.run(["kill", "-TERM", str(pid)])
        for _ in range(40):
            if not pids():
                break
            time.sleep(0.25)
    (DATA / "extensions" / "Monitoring.ini").unlink(missing_ok=True)
    assert not pids(), "Pixelorama did not stop"


def dismiss_reopen_prompt():
    """macOS asks "unexpectedly quit while reopening windows" after SIGTERM-stopped runs; that modal
    stalls start-up. Answer "Don't Reopen" (needs Accessibility for the terminal; harmless if absent)."""
    for pid in pids():
        subprocess.run(["osascript", "-e", f'tell application "System Events" to tell (first process whose '
                        f'unix id is {pid}) to click button "Don\u2019t Reopen" of window 1'],
                       capture_output=True)


def open_like_a_person(path):
    """Fresh instance with the file, as Finder does. Returns (/health, canvas names) of that instance."""
    stop_all()
    subprocess.run(["open", "-a", APP, str(path)], check=True)
    h = None
    for i in range(30):
        h = health()
        if h:
            break
        if i % 6 == 5:
            dismiss_reopen_prompt()
        time.sleep(0.5)
    time.sleep(2)   # let Main._ready()'s command-line open and any deferred work finish
    return h, canvases()


# ---------- build the files ----------
W.mkdir(parents=True, exist_ok=True)
if not health():
    subprocess.run(["open", "-a", APP], check=True)
    for _ in range(30):
        if health():
            break
        time.sleep(0.5)
base = W / "guard_base.pxo"
call("create_canvas", {"width": 8, "height": 8, "name": "guard_base"})
st, js = call("save_project", {"path": str(base)})
assert st == 200 and base.exists(), js

cases = {}


def scene_case(d):
    lay = dict(d["layers"][0]); lay["type"] = 2; lay["name"] = "payload3d"
    d["layers"].append(lay)
    for f in d["frames"]:
        f["cels"].append(dict(f["cels"][0]))


scene = ('[gd_scene load_steps=2 format=3]\n\n[sub_resource type="GDScript" id="s"]\n'
         f'script/source = "{gd_source("pxo_scene", "Node3D")}"\n\n'
         '[node name="Root" type="Node3D"]\nscript = SubResource("s")\n')
cases["pxo_scene"] = pxo_variant(base, W / "pxo_scene.pxo", scene_case, {"scene/0": scene})

res_param = evil_tres("pxo_effect_param")
cases["pxo_effect_param"] = pxo_variant(base, W / "pxo_effect_param.pxo", lambda d: d["layers"][0].__setitem__(
    "effects", [{"name": "x", "shader_path": EFFECT_SHADER, "enabled": True,
                 "params": {"brightness": f'Resource("{res_param}")'}}]))

res_shader = evil_tres("pxo_shader_path")
cases["pxo_shader_path"] = pxo_variant(base, W / "pxo_shader_path.pxo", lambda d: d["layers"][0].__setitem__(
    "effects", [{"name": "x", "shader_path": str(res_shader), "enabled": True}]))

cases["tres_direct"] = evil_tres("tres_direct")

res_ora = evil_tres("ora_attr")
ora = W / "ora_attr.ora"
with zipfile.ZipFile(ora, "w") as z:
    z.writestr("mimetype", "image/openraster")
    z.writestr("stack.xml", f'<?xml version="1.0"?><image w=\'Resource("{res_ora}")\' h="8"><stack></stack></image>')
cases["ora_attr"] = ora

res_ora_ent = evil_tres("ora_entity")
ora_ent = W / "ora_entity.ora"
with zipfile.ZipFile(ora_ent, "w") as z:
    z.writestr("mimetype", "image/openraster")
    z.writestr("stack.xml", f'<?xml version="1.0"?><image w=\'Resource&#40;"{res_ora_ent}"&#41;\' h="8"><stack></stack></image>')
cases["ora_entity"] = ora_ent

# ---------- run ----------
for m in W.glob("*.marker"):
    m.unlink()
results = []
for case, path in cases.items():
    h, names = open_like_a_person(path)
    ran = marker(case).exists()
    print(("RAN    " if ran else "blocked") + f"  {case}  ({path.name})  guard={h and h.get('open_guard')}  canvases={names}")
    results.append((f"{case}: payload did not run (fresh instance, guard={h and h.get('open_guard')})", not ran,
                    "marker written -> code executed"))

if not PROBE:
    h, names = open_like_a_person(base)
    results.append(("genuine .pxo opens through the Finder/open path", bool(names) and "guard_base" in names, names))
    results.append(("boot guard was active in that instance", bool(h) and h.get("open_guard") == "boot", h))
    # Pixelorama rewrites override.cfg from scratch on some preference changes: the extension must
    # notice the missing autoload, fall back to the runtime guard and restore the line.
    cfg = DATA / "override.cfg"
    cfg.write_text(cfg.read_text().replace(GUARD_LINE, ""))
    h, names = open_like_a_person(base)
    results.append(("without the override line the runtime guard takes over", bool(h) and h.get("open_guard") == "runtime", h))
    results.append(("the extension restored the override line", GUARD_LINE in cfg.read_text(), cfg.read_text()))
    h, names = open_like_a_person(base)
    results.append(("next start is guarded from boot again", bool(h) and h.get("open_guard") == "boot", h))

stop_all()
subprocess.run(["open", "-a", APP])   # leave a plain instance running
for f in list(cases.values()) + [base] + list(W.glob("*_payload.tres")) + list(W.glob("*.marker")):
    f.unlink(missing_ok=True)

if PROBE:
    sys.exit(0)
failed = 0
for name, ok, detail in results:
    failed += not ok
    print(("PASS" if ok else "FAIL") + "  " + name + ("" if ok else "  <- " + str(detail)))
print(f"\n{len(results) - failed}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
