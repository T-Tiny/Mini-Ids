"""Capture → Parse → State → Detect → Alert 파이프라인을 묶는 엔진."""
from __future__ import annotations

from typing import Iterable, Optional

from .alert import Alert, AlertSink
from .config import load_config
from .detectors.arp_spoof import ArpSpoofDetector
from .detectors.packet_rules import DnsDetector, HttpDetector, IcmpDetector, SshDetector
from .detectors.portscan import PortScanDetector
from .parse import parse

DETECTORS = {
    "portscan": PortScanDetector,
    "arp": ArpSpoofDetector,
    "dns": DnsDetector,
    "icmp": IcmpDetector,
    "http": HttpDetector,
    "ssh": SshDetector,
}


class MiniIDS:
    def __init__(self, config: Optional[dict] = None, sink: Optional[AlertSink] = None):
        self.cfg = config or load_config()
        self.sink = sink or AlertSink()
        self.detectors = [cls(self.cfg[key], self.sink.emit)
                          for key, cls in DETECTORS.items() if self.cfg[key].get("enabled", True)]
        self.packets = 0
        self.parse_errors = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

    # Scapy sniff(prn=...) 에 그대로 넘길 수 있는 콜백
    def process(self, pkt) -> None:
        self.packets += 1
        try:
            info = parse(pkt)                  # Parse
        except Exception:                      # 깨진 패킷은 건너뛴다
            self.parse_errors += 1
            return
        self.first_ts = self.first_ts if self.first_ts is not None else info.ts
        self.last_ts = info.ts
        for d in self.detectors:               # State + Detect (각 탐지기가 상태를 보관)
            try:
                d.handle(info)
            except Exception as e:             # 한 탐지기 오류로 IDS 전체가 멈추지 않도록
                print(f"[!] {d.name} 처리 오류: {e!r}")

    def run(self, packets: Iterable) -> list[Alert]:
        for pkt in packets:
            self.process(pkt)
        return self.sink.alerts

    def summary(self) -> dict:
        by_rule: dict[str, int] = {}
        for a in self.sink.alerts:
            by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
        return {
            "packets": self.packets,
            "duration_sec": round((self.last_ts or 0) - (self.first_ts or 0), 2),
            "alerts": len(self.sink.alerts),
            "alerts_by_rule": by_rule,
            "detectors": {d.name: d.summary() for d in self.detectors if d.summary()},
        }
