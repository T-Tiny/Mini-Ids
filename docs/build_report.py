#!/usr/bin/env python3
"""results/ 의 실제 실행 결과로 보고서 HTML 을 채우고 PDF 로 변환한다.

  python3 docs/build_report.py --author "홍길동" --repo "github.com/<id>/mini-ids"
  (PDF 변환에는 playwright + chromium 필요: pip install playwright && playwright install chromium)
"""
import argparse
import html
import json
import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LOGS = os.path.join(ROOT, "results", "logs")


def colorize(text: str) -> str:
    out = []
    for line in text.rstrip("\n").splitlines():
        e = html.escape(line)
        if line.startswith("$"):
            e = f'<span class="cmd">{e}</span>'
        e = re.sub(r"\] (HIGH|MEDIUM|LOW)( +)", lambda m: f'] <span class="{m.group(1)[0]}">{m.group(1)}</span>{m.group(2)}', e)
        out.append(e)
    return "\n".join(out)


def log(name, cfg="tuned"):
    with open(os.path.join(LOGS, f"{name}.{cfg}.txt"), encoding="utf-8") as f:
        return colorize(f.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--author", default="")
    ap.add_argument("--repo", default="github.com/&lt;your-id&gt;/mini-ids")
    ap.add_argument("--no-pdf", action="store_true")
    a = ap.parse_args()

    with open(os.path.join(ROOT, "results", "eval_results.json"), encoding="utf-8") as f:
        ev = json.load(f)
    with open(os.path.join(ROOT, "docs", "report_template.html"), encoding="utf-8") as f:
        t = f.read()

    tot = ev["totals"]
    rows = []
    for cname, label in (("default", "default (설정 없음)"), ("tuned", "tuned (config.json)")):
        x = tot[cname]
        rows.append(f"<tr><td>{label}</td><td class='c'>{x['TP']}</td><td class='c'>{x['FN']}</td>"
                    f"<td class='c'>{x['FP']}</td><td class='c'>{x['TN']}</td>"
                    f"<td class='c'><b>{x['detection_rate']:.1%}</b></td><td class='c'><b>{x['false_positive_rate']:.1%}</b></td>"
                    f"<td class='c'>{x['precision']:.1%}</td></tr>")

    sc = ['<table><tr><th style="width:4%">#</th><th style="width:40%">시나리오</th><th style="width:7%">정답</th>'
          '<th class="c" style="width:8%">default</th><th class="c" style="width:8%">tuned</th><th>울린 규칙 (tuned)</th></tr>']
    for r in ev["scenarios"]:
        num = r["name"][1:3]
        d, tu = r["default"]["result"], r["tuned"]["result"]
        rules = ", ".join(x.replace("_", "_<wbr>") for x in r["tuned"]["rules"]) or "-"
        sc.append(f"<tr><td>{num}</td><td>{html.escape(r['description'])}</td>"
                  f"<td>{'공격' if r['label'] == 'attack' else '정상'}</td>"
                  f"<td class='c {d}'>{d}</td><td class='c {tu}'>{tu}</td><td class='small'>{rules}</td></tr>")
    sc.append("</table>")

    with open(os.path.join(ROOT, "results", "live_lo_run.txt"), encoding="utf-8") as f:
        live = f.read().split("\n{")[0]
    live = "$ sudo python3 ids.py -i lo -t 20 --summary   # 다른 터미널: python3 tools/live_demo_scan.py\n" + live

    t = (t.replace("{{AUTHOR}}", html.escape(a.author) or "&nbsp;" * 12)
          .replace("{{REPO}}", a.repo)
          .replace("{{LOG_S02}}", log("S02_syn_scan"))
          .replace("{{LOG_S03}}", log("S03_stealth_scan"))
          .replace("{{LOG_S08}}", log("S08_arp_spoofing"))
          .replace("{{LOG_S12}}", log("S12_dns_tunnel"))
          .replace("{{LOG_S17}}", log("S17_http_attacks"))
          .replace("{{LOG_S18}}", log("S18_http_plain_login"))
          .replace("{{LOG_S21}}", log("S21_ssh_bruteforce"))
          .replace("{{LOG_LIVE}}", colorize(live))
          .replace("{{TOTALS_ROWS}}", "\n".join(rows))
          .replace("{{SCENARIO_TABLE}}", "\n".join(sc)))
    for k in ("TP", "FN", "FP", "TN"):
        t = t.replace("{{T_%s}}" % k, str(tot["tuned"][k]))
    assert "{{" not in t, re.findall(r"\{\{\w+\}\}", t)

    out_html = os.path.join(ROOT, "docs", "report.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(t)
    print("[+] docs/report.html")
    if a.no_pdf:
        return
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        pg.goto("file://" + os.path.abspath(out_html))
        pg.pdf(path=os.path.join(ROOT, "docs", "report.pdf"), format="A4", print_background=True,
               display_header_footer=True, header_template="<span></span>",
               footer_template='<div style="width:100%;text-align:center;font-size:8px;color:#8a94a3;">'
                               'Mission Mini IDS · <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
               margin={"top": "15mm", "bottom": "16mm", "left": "16mm", "right": "16mm"})
        b.close()
    print("[+] docs/report.pdf")


if __name__ == "__main__":
    main()
