#!/usr/bin/env python3
"""모든 시나리오 PCAP 을 IDS 로 돌려 TP / FP / FN / TN 을 집계한다.

두 가지 설정으로 비교:
  default : 설정 파일 없음 (순수 학습 모드, 차단 도메인 없음)
  tuned   : config.json (게이트웨이 정적 등록 + 이중화 MAC 허용 + 차단 도메인)
"""
from __future__ import annotations

import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scapy.utils import rdpcap  # noqa: E402

from mini_ids.alert import AlertSink  # noqa: E402
from mini_ids.config import load_config  # noqa: E402
from mini_ids.engine import MiniIDS  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCN = os.path.join(ROOT, "scenarios")
RES = os.path.join(ROOT, "results")

CONFIGS = {"default": None, "tuned": os.path.join(ROOT, "config.json")}


def run_one(pcap: str, cfg_path):
    buf = io.StringIO()
    ids = MiniIDS(load_config(cfg_path), AlertSink(stream=buf, color=False))
    ids.run(rdpcap(pcap))
    return ids, buf.getvalue()


def judge(sc: dict, alerts) -> str:
    fired = {a.rule for a in alerts}
    if sc["label"] == "attack":
        return "TP" if fired & set(sc["expected_rules"]) else "FN"
    return "FP" if fired else "TN"


def main():
    with open(os.path.join(SCN, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    os.makedirs(os.path.join(RES, "logs"), exist_ok=True)

    rows = []
    for sc in manifest:
        row = {"name": sc["name"], "label": sc["label"], "description": sc["description"],
               "expected_rules": sc["expected_rules"], "design_note": sc.get("design_note", "")}
        for cname, cpath in CONFIGS.items():
            ids, log = run_one(os.path.join(SCN, sc["pcap"]), cpath)
            alerts = ids.sink.alerts
            row[cname] = {
                "result": judge(sc, alerts),
                "alerts": len(alerts),
                "rules": sorted({a.rule for a in alerts}),
                "unexpected_rules": sorted({a.rule for a in alerts} - set(sc["expected_rules"])),
                "first_alert_delay_sec": round(alerts[0].ts - ids.first_ts, 2) if alerts else None,
                "packets": ids.packets,
            }
            with open(os.path.join(RES, "logs", f"{sc['name']}.{cname}.txt"), "w", encoding="utf-8") as f:
                f.write(f"$ python3 ids.py -r scenarios/{sc['pcap']}" + (" -c config.json" if cpath else "") + "\n")
                f.write(log)
                s = ids.summary()
                f.write(f"\n[*] 패킷 {s['packets']}개 / {s['duration_sec']}초 분석, 경고 {s['alerts']}건 {s['alerts_by_rule']}\n")
            with open(os.path.join(RES, "logs", f"{sc['name']}.{cname}.jsonl"), "w", encoding="utf-8") as f:
                for a in alerts:
                    f.write(json.dumps(a.to_dict(), ensure_ascii=False) + "\n")
        rows.append(row)

    # ---- 집계
    totals = {}
    for cname in CONFIGS:
        cnt = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
        for r in rows:
            cnt[r[cname]["result"]] += 1
        tp, fp, fn, tn = cnt["TP"], cnt["FP"], cnt["FN"], cnt["TN"]
        cnt["detection_rate"] = round(tp / (tp + fn), 3) if tp + fn else None
        cnt["false_positive_rate"] = round(fp / (fp + tn), 3) if fp + tn else None
        cnt["precision"] = round(tp / (tp + fp), 3) if tp + fp else None
        totals[cname] = cnt

    with open(os.path.join(RES, "eval_results.json"), "w", encoding="utf-8") as f:
        json.dump({"totals": totals, "scenarios": rows}, f, ensure_ascii=False, indent=2)

    # ---- 표 출력 (README/보고서용 Markdown)
    lines = ["| 시나리오 | 정답 | default | tuned | 울린 규칙(tuned) |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['name']} | {r['label']} | {r['default']['result']} | {r['tuned']['result']} | "
                     f"{', '.join(r['tuned']['rules']) or '-'} |")
    lines.append("")
    for cname, t in totals.items():
        lines.append(f"- **{cname}**: TP {t['TP']} / FN {t['FN']} / FP {t['FP']} / TN {t['TN']} → "
                     f"탐지율 {t['detection_rate']:.1%}, 오탐률 {t['false_positive_rate']:.1%}, 정밀도 {t['precision']:.1%}")
    md = "\n".join(lines)
    with open(os.path.join(RES, "eval_table.md"), "w", encoding="utf-8") as f:
        f.write(md + "\n")
    print(md)


if __name__ == "__main__":
    main()
