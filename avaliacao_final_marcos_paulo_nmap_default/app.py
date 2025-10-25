import os, json, sqlite3, argparse
from datetime import datetime
from flask import Flask, render_template, request, send_from_directory, jsonify, Response
from markdown_it import MarkdownIt
import yaml

from scanners.common import artifact_dir_for, ensure_dir
from scanners.zap import run_zap_baseline
from scanners.nikto import run_nikto
from scanners.nmap import run_nmap
from report.builder import build_reports

APP_DB = "scanner.db"
ensure_dir("artifacts")
ensure_dir("db")

with open("db/schema.sql","r",encoding="utf-8") as f:
    schema = f.read()
conn = sqlite3.connect(APP_DB)
conn.executescript(schema)
conn.commit()
conn.close()

app = Flask(__name__, static_folder=None)
md = MarkdownIt()

def save_scan_record(target, artifacts_dir, summary_dict):
    conn = sqlite3.connect(APP_DB)
    conn.execute("INSERT INTO scans (target, timestamp, artifacts_dir, summary_json) VALUES (?,?,?,?)",
                 (target, datetime.now().isoformat(timespec="seconds"), artifacts_dir, json.dumps(summary_dict, ensure_ascii=False)))
    conn.commit()
    conn.close()

def list_scans():
    conn = sqlite3.connect(APP_DB)
    cur = conn.cursor()
    cur.execute("SELECT id, target, timestamp, artifacts_dir, summary_json FROM scans ORDER BY id DESC LIMIT 100")
    rows = cur.fetchall()
    conn.close()
    out = []
    for (id_, target, ts, adir, sj) in rows:
        artifacts_name = os.path.basename(adir.rstrip("/"))
        out.append({
            "id": id_,
            "target": target,
            "timestamp": ts,
            "artifacts_dir": adir,
            "artifacts_name": artifacts_name,
            "summary": json.loads(sj)
        })
    return out

def map_to_owasp(zap_out: str, nikto_out: str, nmap_out: str):
    owasp_keys = [
        "A01: Broken Access Control",
        "A02: Cryptographic Failures",
        "A03: Injection",
        "A04: Insecure Design",
        "A05: Security Misconfiguration",
        "A06: Vulnerable and Outdated Components",
        "A07: Identification and Authentication Failures",
        "A08: Software and Data Integrity Failures",
        "A09: Security Logging and Monitoring Failures",
        "A10: Server-Side Request Forgery",
    ]
    owasp = {k: [] for k in owasp_keys}

    zap_out = zap_out or ""
    nikto_out = nikto_out or ""
    nmap_out = nmap_out or ""

    if "Missing Anti-clickjacking Header" in zap_out or "X-Frame-Options" in zap_out:
        owasp["A05: Security Misconfiguration"].append("Headers de proteção ausentes (X-Frame-Options).")
    if "X-Content-Type-Options" in zap_out:
        owasp["A05: Security Misconfiguration"].append("X-Content-Type-Options ausente.")
    if "X-XSS-Protection" in zap_out:
        owasp["A05: Security Misconfiguration"].append("X-XSS-Protection ausente.")
    if "Strict-Transport-Security" in zap_out:
        owasp["A02: Cryptographic Failures"].append("HSTS ausente.")

    if "Outdated" in nikto_out or "Server leaks in headers" in nikto_out:
        owasp["A06: Vulnerable and Outdated Components"].append("Tecnologias/versões possivelmente desatualizadas.")
    if "X-Frame-Options header is not present" in nikto_out:
        owasp["A05: Security Misconfiguration"].append("Falta X-Frame-Options (Nikto).")
    if "cookie(s) without 'HttpOnly'" in nikto_out or "without 'Secure'" in nikto_out:
        owasp["A02: Cryptographic Failures"].append("Cookies sem flags de segurança.")

    if "ssl-enum-ciphers" in nmap_out and "weak" in nmap_out.lower():
        owasp["A02: Cryptographic Failures"].append("Cifras TLS fracas/expostas.")

    return owasp

@app.route("/", methods=["GET"])
def home():
    cfg = {}
    if os.path.exists("config.yaml"):
        with open("config.yaml","r",encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    defaults = {
        "enable_zap": bool(cfg.get("defaults",{}).get("enable_zap", cfg.get("enable_zap", True))),
        "enable_nikto": bool(cfg.get("defaults",{}).get("enable_nikto", True)),
        "enable_nmap": bool(cfg.get("defaults",{}).get("enable_nmap", True)),
        "fast_mode": bool(cfg.get("defaults",{}).get("fast_mode", cfg.get("fast_mode", False))),
        "nmap_ports": cfg.get("defaults",{}).get("nmap_ports", cfg.get("nmap_ports"))
    }
    scans = list_scans()
    return render_template("index.html", scans=scans, defaults=defaults)

def run_full_scan(target: str, docker_zap: bool = True, enable_zap=True, enable_nikto=False, enable_nmap=True, fast_mode=False, cfg_ports=None):
    config = {}
    if os.path.exists("config.yaml"):
        with open("config.yaml","r",encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    t_zap  = int(config.get("timeouts",{}).get("zap_minutes",5))
    t_nik  = int(config.get("timeouts",{}).get("nikto_minutes",5))
    t_nmap = int(config.get("timeouts",{}).get("nmap_minutes",3))

    if cfg_ports is None:
        cfg_ports = config.get("defaults",{}).get("nmap_ports", config.get("nmap_ports"))
    if fast_mode is None:
        fast_mode = bool(config.get("defaults",{}).get("fast_mode", config.get("fast_mode", False)))

    artifacts_dir = artifact_dir_for(target)

    if enable_zap:
        zap_res = run_zap_baseline(target, artifacts_dir, timeout_minutes=t_zap, docker=docker_zap)
    else:
        zap_res = {"status":"skipped","report_html":"","raw_output":"ZAP desativado."}

    if enable_nikto:
        nikto_res = run_nikto(target, artifacts_dir, timeout_minutes=t_nik, fast=fast_mode)
    else:
        nikto_res = {"status":"skipped","report_txt":"","raw_output":"Nikto desativado."}

    if enable_nmap:
        nmap_res = run_nmap(target, artifacts_dir, timeout_minutes=t_nmap, fast=fast_mode, ports=cfg_ports)
    else:
        nmap_res = {"status":"skipped","report_xml":"","raw_output":"Nmap desativado."}

    owasp_map = map_to_owasp(zap_res.get("raw_output"), nikto_res.get("raw_output"), nmap_res.get("raw_output"))

    summary = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "zap": zap_res,
        "nikto": nikto_res,
        "nmap": nmap_res,
        "owasp": owasp_map
    }

    build_reports(summary, artifacts_dir)

    with open(os.path.join(artifacts_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return artifacts_dir, summary

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target","").strip()
    docker_zap = request.form.get("docker_zap") == "on"

    enable_zap   = request.form.get("svc_zap")  == "on"
    enable_nikto = request.form.get("svc_nikto")== "on"
    enable_nmap  = request.form.get("svc_nmap") == "on"
    fast_mode    = request.form.get("fast_mode")== "on"
    nmap_ports   = request.form.get("nmap_ports","").strip() or None

    if not (target.startswith("http://") or target.startswith("https://")):
        return "Forneça uma URL válida (http/https).", 400

    artifacts_dir, summary = run_full_scan(
        target,
        docker_zap=docker_zap,
        enable_zap=enable_zap,
        enable_nikto=enable_nikto,
        enable_nmap=enable_nmap,
        fast_mode=fast_mode,
        cfg_ports=nmap_ports
    )
    save_scan_record(target, artifacts_dir, summary)
    return jsonify({"ok": True, "artifacts": artifacts_dir, "summary": summary})

@app.route("/artifacts/<path:subpath>")
def serve_artifacts(subpath):
    d = os.path.join("artifacts", subpath)
    root = os.path.dirname(d)
    fname = os.path.basename(d)
    return send_from_directory(root, fname)

@app.route("/export")
def export_view():
    fmt = request.args.get("fmt","csv")
    scans = list_scans()
    if fmt == "json":
        return jsonify(scans)
    lines = ["id,timestamp,target,artifacts_dir"]
    for s in scans:
        lines.append(f'{s["id"]},{s["timestamp"]},{s["target"]},{s["artifacts_dir"]}')
    csv = "\n".join(lines)
    return Response(csv, mimetype="text/csv")

def main_cli(target: str):
    artifacts_dir, summary = run_full_scan(target, docker_zap=False,
                                           enable_zap=False, enable_nikto=False, enable_nmap=True,
                                           fast_mode=True)
    save_scan_record(target, artifacts_dir, summary)
    print(json.dumps({"ok": True, "artifacts": artifacts_dir, "summary": summary}, ensure_ascii=False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", action="store_true", help="Rodar no modo CLI e sair")
    parser.add_argument("--target", type=str, help="URL alvo")
    args = parser.parse_args()
    if args.cli:
        if not args.target:
            raise SystemExit("Use --target <URL>")
        main_cli(args.target)
    else:
        app.run(host="127.0.0.1", port=5000, debug=True)
