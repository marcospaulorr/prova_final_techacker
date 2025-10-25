import os
from .common import run_cmd

def run_nikto(target: str, outdir: str, timeout_minutes=5, fast=False):
    report_txt = os.path.join(outdir, "nikto_report.txt")
    if fast:
        cmd = f'bash -lc "nikto -h {target} -ask no -Plugins headers,ssl -maxtime 90s -timeout 10 -Display V 2>&1 | tee {report_txt}"'
    else:
        cmd = f'bash -lc "nikto -h {target} -ask no -Display V 2>&1 | tee {report_txt}"'
    code, out = run_cmd(cmd, timeout=timeout_minutes*60)
    return {
        "status": "ok" if code == 0 else f"warn_or_error:{code}",
        "report_txt": report_txt,
        "raw_output": out
    }
