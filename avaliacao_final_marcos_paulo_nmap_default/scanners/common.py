import os, subprocess, shlex, pathlib
from datetime import datetime
from slugify import slugify

ARTIFACTS_DIR = "artifacts"

def ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def ensure_dir(p):
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def run_cmd(cmd: str, cwd=None, timeout=None, env=None):
    proc = subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
        env=env
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        proc.kill()
        return 124, "[TIMEOUT] " + cmd

def target_to_slug(target: str) -> str:
    return slugify(target, lowercase=True, max_length=80)

def artifact_dir_for(target: str) -> str:
    s = target_to_slug(target)
    d = os.path.join(ARTIFACTS_DIR, f"{ts()}_{s}")
    ensure_dir(d)
    return d
