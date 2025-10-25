import os
from urllib.parse import urlparse
from .common import run_cmd

def run_nmap(target: str, outdir: str, timeout_minutes=3, fast=False, ports=None):
    xml_path = os.path.join(outdir, "nmap_report.xml")

    # extrai host se for URL
    host = target
    if target.startswith(("http://","https://")):
        parsed = urlparse(target)
        host = parsed.hostname or target

    base = "nmap -sV -Pn"
    if fast:
        base += f" -T4 --max-retries 1 --host-timeout {timeout_minutes*60}s"
        if not ports:
            ports = "80,443"
    if ports:
        base += f" -p {ports}"

    base += " --script ssl-enum-ciphers"
    cmd = f"{base} {host} -oX {xml_path}"

    code, out = run_cmd(cmd, timeout=timeout_minutes*60)
    return {
        "status": "ok" if code == 0 else f"warn_or_error:{code}",
        "report_xml": xml_path,
        "raw_output": out
    }
