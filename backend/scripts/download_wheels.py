import urllib.request
import json
import os
import sys

pkg_versions = {
    "sqlalchemy": "2.0.38",
    "alembic": "1.14.1",
    "asyncpg": "0.30.0",
    "psycopg_binary": "3.2.4",
    "aiosqlite": "0.21.0",
}

target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "wheels"))
os.makedirs(target_dir, exist_ok=True)

for pkg, ver in pkg_versions.items():
    print(f"[{pkg}] Fetching release metadata for v{ver}...", flush=True)
    req = urllib.request.Request(
        f"https://pypi.org/pypi/{pkg}/{ver}/json",
        headers={"User-Agent": "TrustVault-FastInstaller/1.0"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    urls = data.get("urls", [])
    matching_url = None
    filename = None
    for item in urls:
        fn = item.get("filename", "")
        if "cp313-cp313-win_amd64.whl" in fn or "py3-none-any.whl" in fn or "cp313-win_amd64.whl" in fn:
            matching_url = item.get("url")
            filename = fn
            break

    if matching_url and filename:
        # Use fast mirror for package binaries
        fast_url = matching_url.replace("https://files.pythonhosted.org/", "https://pypi.tuna.tsinghua.edu.cn/")
        target_path = os.path.join(target_dir, filename)
        if os.path.exists(target_path) and os.path.getsize(target_path) > 10000:
            print(f"[{pkg}] Already exists: {filename}", flush=True)
            continue
        print(f"[{pkg}] Downloading from {fast_url}...", flush=True)
        urllib.request.urlretrieve(fast_url, target_path)
        print(f"[{pkg}] Saved {filename} ({os.path.getsize(target_path)} bytes)", flush=True)
    else:
        print(f"[{pkg}] Warning: no matching wheel found in {len(urls)} assets", flush=True)

print("ALL WHEELS DOWNLOADED SUCCESSFULLY!", flush=True)
