#!/usr/bin/env python3
"""Build release archives; only the radiusd executable is needed at runtime."""
import concurrent.futures
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = os.environ.get("BORDER_VERSION", "v0.5.8-alpha.1")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+[-a-zA-Z0-9.]*", VERSION):
    raise ValueError("Invalid release version")
DIST = ROOT / "dist"
DIST.mkdir(exist_ok=True)
licenses = DIST / "licenses"
if licenses.exists():
    shutil.rmtree(licenses)
licenses.mkdir(exist_ok=True)
raw = subprocess.check_output(["go", "list", "-deps", "-json", "./cmd/radiusd"], cwd=ROOT, text=True)
decoder, modules = json.JSONDecoder(), {}
while raw.strip():
    obj, offset = decoder.raw_decode(raw.lstrip())
    raw = raw.lstrip()[offset:]
    mod = obj.get("Module", {})
    if mod and not mod.get("Main"):
        modules[mod["Path"]] = mod
manifest = []
for name, mod in sorted(modules.items()):
    source = Path(mod["Dir"])
    destination = licenses / name.replace("/", "_")
    destination.mkdir(exist_ok=True)
    notices = [p for p in source.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "PATENTS", "AUTHORS"))]
    if not notices:
        raise RuntimeError(f"No license found for {name}; inspect before release")
    for notice in notices:
        shutil.copy2(notice, destination / notice.name)
    manifest.append({"module": name, "version": mod.get("Version"), "source": "https://proxy.golang.org/" + "".join("!" + c.lower() if c.isupper() else c for c in name) + "/@v/" + mod.get("Version", "") + ".zip"})
(licenses / "modules.json").write_text(json.dumps(manifest, indent=2) + "\n")
goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
shutil.copy2(goroot / "LICENSE", licenses / "Go-LICENSE")
if (goroot / "PATENTS").exists():
    shutil.copy2(goroot / "PATENTS", licenses / "Go-PATENTS")

if "--licenses-only" in sys.argv:
    print("Collected dependency licenses")
    sys.exit(0)

def build(target):
    target_os, arch = target
    folder = DIST / ("border-" + VERSION + "-" + target_os + "-" + arch)
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir()
    env = dict(os.environ, CGO_ENABLED="0", GOOS=target_os, GOARCH=arch)
    subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w -X main.version=" + VERSION, "-o", str(folder / "radiusd"), "./cmd/radiusd"], cwd=ROOT, env=env, check=True)
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY.md", "README.md", ".env.example"):
        shutil.copy2(ROOT / name, folder / name)
    shutil.copytree(licenses, folder / "licenses", dirs_exist_ok=True)
    archive = DIST / (folder.name + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(folder, arcname=folder.name)
    return archive

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    archives = list(executor.map(build, [("linux", "amd64"), ("linux", "arm64"), ("darwin", "arm64")]))
(DIST / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in sorted(archives)))
print("Built:", ", ".join(p.name for p in archives))
