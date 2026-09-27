#!/usr/bin/env python3
"""Mini IDS 실행기.

  실시간 탐지 : sudo python3 ids.py -i eth0 -c config.json
  PCAP 분석   : python3 ids.py -r capture.pcap -c config.json
"""
from __future__ import annotations

import argparse
import json
import sys

from mini_ids.alert import AlertSink
from mini_ids.config import load_config
from mini_ids.engine import MiniIDS


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mini IDS - Port Scan / ARP Spoofing / 특정 패킷 탐지")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--iface", help="실시간 캡처할 인터페이스 (root 권한 필요)")
    src.add_argument("-r", "--read", help="분석할 pcap 파일")
    ap.add_argument("-c", "--config", help="설정 파일(JSON)")
    ap.add_argument("-f", "--filter", default="arp or tcp or udp or icmp", help="BPF 캡처 필터")
    ap.add_argument("-l", "--log", help="경고를 JSON Lines 로 저장할 경로")
    ap.add_argument("-t", "--timeout", type=int, help="실시간 캡처 시간(초)")
    ap.add_argument("-q", "--quiet", action="store_true", help="경고를 화면에 출력하지 않음")
    ap.add_argument("--summary", action="store_true", help="종료 시 요약(JSON) 출력")
    args = ap.parse_args(argv)

    from scapy.all import PcapReader, sniff  # Capture 단계 (import 가 느려서 여기서)

    ids = MiniIDS(load_config(args.config), AlertSink(args.log, quiet=args.quiet))
    try:
        if args.read:
            with PcapReader(args.read) as reader:
                ids.run(reader)
        else:
            print(f"[*] {args.iface} 에서 캡처 시작 (filter='{args.filter}') - Ctrl+C 로 종료")
            try:
                sniff(iface=args.iface, filter=args.filter, prn=ids.process, store=False, timeout=args.timeout)
            except Exception as e:
                # libpcap(리눅스)/Npcap(윈도우)이 없으면 BPF 필터를 컴파일할 수 없다 → 필터 없이 재시도
                if "filter" not in str(e).lower():
                    raise
                print(f"[!] BPF 필터 사용 불가({e}) → 필터 없이 캡처합니다")
                sniff(iface=args.iface, prn=ids.process, store=False, timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        ids.sink.close()

    s = ids.summary()
    print(f"\n[*] 패킷 {s['packets']}개 / {s['duration_sec']}초 분석, 경고 {s['alerts']}건 {s['alerts_by_rule']}")
    if args.summary:
        print(json.dumps(s["detectors"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
