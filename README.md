# Mini-Ids
구조: Capture -> Parse -> State -> Detect -> Alert 
탐지 항목: Port Scan, ARP Spoofing, 특정 패킷(DNS/ICMP/HTTP/SSH)

```
mini-ids/
├── ids.py                      # 실행기 (실시간 -i / pcap -r)
├── config.json                 # 환경별 설정 (게이트웨이 정적 등록, 허용 MAC, 차단 도메인, 화이트리스트)
├── mini_ids/
│   ├── parse.py                # 필드 추출
│   ├── config.py               # 기본 임계값
│   ├── engine.py               # 파이프라인
│   ├── alert.py
│   └── detectors/
│       ├── base.py             # SlidingWindow, Cooldown
│       ├── portscan.py
│       ├── arp_spoof.py
│       └── packet_rules.py     # DNS / ICMP / HTTP / SSH
├── tools/
│   ├── gen_scenarios.py        # 정답이 붙은 테스트 PCAP 25개 생성 (Packet Crafting)
│   ├── evaluate.py             # TP/FP/FN/TN 자동 집계
│   └── live_demo_scan.py       # 실시간 모드 시연용 트래픽
├── scenarios/                  # 생성된 PCAP + manifest.json (Wireshark 로 열어볼 수 있음)
├── results/                    # 평가 결과, 시나리오별 실행 로그
├── tests/test_detectors.py     # 단위 테스트 21개
└── docs/report.pdf             # 보고서
```
