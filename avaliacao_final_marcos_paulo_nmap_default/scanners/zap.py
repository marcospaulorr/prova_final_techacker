import os, shutil
from .common import run_cmd

def run_zap_baseline(target: str, outdir: str, timeout_minutes=5, docker=True):
    """
    Tenta ZAP Baseline (Docker). Sem Docker: tenta zap-baseline.py local;
    se não existir (snap), usa fallback Quick Scan via 'zaproxy -cmd'.
    """
    baseline_html = os.path.join(outdir, "zap_baseline_report.html")
    quickscan_xml = os.path.join(outdir, "zap_quickscan_report.xml")

    if docker:
        cmd = f"docker run --rm -v {os.path.abspath(outdir)}:/zap/wrk owasp/zap2docker-stable zap-baseline.py -t {target} -r zap_baseline_report.html -I -m {timeout_minutes}"
        code, out = run_cmd(cmd, timeout=timeout_minutes*60)
        return {
            "status": "ok" if code in (0,1) else f"error:{code}",
            "report_html": baseline_html,
            "raw_output": out
        }

    baseline_path = shutil.which("zap-baseline.py")
    if baseline_path:
        cmd = f"{baseline_path} -t {target} -r {baseline_html} -I -m {timeout_minutes}"
        code, out = run_cmd(cmd, timeout=timeout_minutes*60)
        return {
            "status": "ok" if code in (0,1) else f"error:{code}",
            "report_html": baseline_html,
            "raw_output": out
        }

    # Quick Scan (snap) usando caminho absoluto
    zap_bin = shutil.which("zaproxy") or "zaproxy"
    quickscan_xml_abs = os.path.abspath(quickscan_xml)
    cmd = f"{zap_bin} -cmd -quickurl {target} -quickprogress -quickout {quickscan_xml_abs}"
    code, out = run_cmd(cmd, timeout=timeout_minutes*60)
    status = "ok" if code == 0 else f"warn_or_error:{code}"
    return {
        "status": status,
        "report_html": quickscan_xml_abs,
        "raw_output": out
    }
