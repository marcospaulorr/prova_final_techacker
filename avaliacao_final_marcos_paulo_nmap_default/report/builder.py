import os
from jinja2 import Environment, FileSystemLoader

def build_reports(aggregated: dict, outdir: str):
    env = Environment(loader=FileSystemLoader("report/templates"))
    html_tpl = env.get_template("report.html.j2")
    html = html_tpl.render(data=aggregated)
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html)

    md_tpl = env.get_template("report.md.j2")
    md = md_tpl.render(data=aggregated)
    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as f:
        f.write(md)
