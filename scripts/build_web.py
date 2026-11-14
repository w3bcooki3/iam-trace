"""Assemble the static web page into web/dist.

    python scripts/build_web.py [--pyodide DIR]

Copies the page, its scripts, fonts and the example account export; zips the iamtrace package
as iamtrace.zip, and the action catalog as catalog.zip when one is present. The result is a
plain static directory for GitHub Pages (or any static host).

With --pyodide DIR (an unpacked `pyodide` npm package of the version named in index.html), the
Python runtime is copied into the site and the page's Content-Security-Policy is narrowed to the
site's own origin: no third-party code is loaded at all. The pages workflow always does this.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
DIST = WEB / "dist"
PKG = ROOT / "src" / "iamtrace"
CATALOG = PKG / "catalog" / "data"


def zip_dir(src: Path, dest: Path, arc_root: str, skip_catalog: bool = False) -> int:
    count = 0
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src.rglob("*")):
            if f.is_dir() or "__pycache__" in f.parts:
                continue
            rel = f.relative_to(src)
            if skip_catalog and rel.parts[:2] == ("catalog", "data"):
                continue
            z.write(f, Path(arc_root) / rel if arc_root else rel)
            count += 1
    return count


PYODIDE_FILES = ("pyodide.mjs", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json")
CDN = "https://cdn.jsdelivr.net"


def bundle_pyodide(src: Path) -> None:
    html = (DIST / "index.html").read_text()
    wanted = re.search(r'name="pyodide-url" content="[^"]*/v([0-9.]+)/full/"', html)
    meta = json.loads((src / "package.json").read_text())
    if not wanted or meta.get("version") != wanted.group(1):
        raise SystemExit(f"--pyodide must be version {wanted.group(1) if wanted else '?'}, got {meta.get('version')}")
    (DIST / "pyodide").mkdir()
    for name in PYODIDE_FILES:
        shutil.copy2(src / name, DIST / "pyodide" / name)
    html = re.sub(r'(name="pyodide-url" content=")[^"]*(")', r"\1pyodide/\2", html)
    html = html.replace(f" {CDN}", "")
    if CDN in html:
        raise SystemExit("index.html still references the CDN after bundling")
    (DIST / "index.html").write_text(html)
    print("pyodide: bundled; the page loads nothing from third parties")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pyodide", type=Path, help="unpacked pyodide npm package to bundle")
    args = ap.parse_args()
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    for name in ("index.html", "theme.js", "app.js", "graph.js", "examples.js", "style.css"):
        shutil.copy2(WEB / name, DIST / name)
    shutil.copytree(WEB / "fonts", DIST / "fonts")
    (DIST / "examples").mkdir()
    shutil.copy2(ROOT / "examples" / "account" / "auth-details.json", DIST / "examples" / "auth-details.json")
    n = zip_dir(PKG, DIST / "iamtrace.zip", "iamtrace", skip_catalog=True)
    print(f"iamtrace.zip: {n} files")
    if (CATALOG / "services").is_dir():
        n = zip_dir(CATALOG, DIST / "catalog.zip", "")
        print(f"catalog.zip: {n} files")
    else:
        print("no catalog in src/iamtrace/catalog/data; the page will run without Diff")
    if args.pyodide:
        bundle_pyodide(args.pyodide)
    return 0


if __name__ == "__main__":
    sys.exit(main())
