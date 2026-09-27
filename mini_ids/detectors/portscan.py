"""Port Scan 탐지 — "짧은 시간에 다수 포트 접근".

탐지 기준
  1) 수직 스캔(Vertical) : 같은 출발지가 같은 목적지의 서로 다른 포트를
                           window_sec 안에 port_threshold 개 이상 두드림
  2) 수평 스캔(Horizontal): 같은 출발지가 같은 포트로 서로 다른 호스트를
                           window_sec 안에 host_threshold 대 이상 두드림 (예: 22번 sweep)
  3) 스텔스 스캔 패킷     : 정상 TCP 에서는 나오지 않는 플래그 조합
                           NULL(플래그 없음) / FIN 단독 / XMAS(FIN+PSH+URG)

'접근(probe)'으로 세는 패킷
  - TCP : SYN 이면서 ACK 가 없는 패킷 (연결 시작) + 위의 스텔스 플래그 패킷
  - UDP : 출발지 포트가 1024 이상인 패킷 (클라이언트가 보낸 요청)
          → DNS 서버(53)가 클라이언트의 임의 포트로 보내는 응답을 스캔으로 오인하지 않기 위함
"""
from __future__ import annotations

from collections import defaultdict

from ..alert import Alert
from ..parse import PacketInfo
from .base import Cooldown, Detector, SlidingWindow

STEALTH_FLAGS = {"": "NULL", "F": "FIN", "FPU": "XMAS"}


class PortScanDetector(Detector):
    name = "PORTSCAN"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        w = cfg["window_sec"]
        self.vertical = SlidingWindow(w)     # (src, dst)   -> dport
        self.horizontal = SlidingWindow(w)   # (src, dport) -> dst
        self.cool = Cooldown(cfg["cooldown_sec"])
        self.whitelist = set(cfg.get("whitelist_src", []))
        self.suspects: set[tuple[str, str]] = set()                   # (scanner, victim)
        self.open_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
        self.probed: dict[tuple[str, str], set[int]] = defaultdict(set)

    @staticmethod
    def _is_probe(p: PacketInfo) -> tuple[bool, str | None]:
        if p.proto == "TCP":
            f = p.tcp_flags
            if "S" in f and "A" not in f:
                return True, None
            ordered = "".join(sorted(f))
            for k, name in STEALTH_FLAGS.items():
                if ordered == "".join(sorted(k)):
                    return True, name
            return False, None
        if p.proto == "UDP":
            return (p.sport is not None and p.sport >= 1024), None
        return False, None

    def handle(self, p: PacketInfo) -> None:
        if p.proto not in ("TCP", "UDP") or p.src_ip is None:
            return

        # 스캔 의심 쌍에 대해 SYN/ACK 응답 = 열린 포트 (보고용 부가 정보)
        if p.proto == "TCP" and "S" in p.tcp_flags and "A" in p.tcp_flags:
            key = (p.dst_ip, p.src_ip)
            if key in self.suspects:
                self.open_ports[key].add(p.sport)
            return

        is_probe, stealth = self._is_probe(p)
        if not is_probe or p.src_ip in self.whitelist:
            return

        src, dst, dport, ts = p.src_ip, p.dst_ip, p.dport, p.ts
        self.probed[(src, dst)].add(dport)

        # 규칙 3: 스텔스 플래그 → 한 패킷만으로도 시그니처 탐지
        if stealth and self.cool.ready(("stealth", src, stealth), ts):
            self.emit(Alert(ts, self.name, "STEALTH_SCAN_PACKET", "MEDIUM",
                            f"{src} → {dst}:{dport} 비정상 TCP 플래그({stealth} scan)",
                            src, dst, {"flags": p.tcp_flags, "scan_type": stealth}))

        # 규칙 1: 수직 스캔
        self.vertical.add((src, dst), ts, (p.proto, dport))
        n_ports = self.vertical.distinct((src, dst))
        if n_ports >= self.cfg["port_threshold"]:
            self.suspects.add((src, dst))
            if self.cool.ready(("v", src, dst), ts):
                sample = sorted({v[1] for v in self.vertical.values((src, dst))})[:10]
                self.emit(Alert(ts, self.name, "PORT_SCAN_VERTICAL", "MEDIUM",
                                f"{src} → {dst}: {self.cfg['window_sec']}초 안에 서로 다른 "
                                f"{p.proto} 포트 {n_ports}개 접근",
                                src, dst, {"distinct_ports": n_ports, "proto": p.proto,
                                           "sample_ports": sample, "scan_type": stealth or ("SYN" if p.proto == "TCP" else "UDP")}))

        # 규칙 2: 수평 스캔
        self.horizontal.add((src, dport), ts, dst)
        n_hosts = self.horizontal.distinct((src, dport))
        if n_hosts >= self.cfg["host_threshold"] and self.cool.ready(("h", src, dport), ts):
            self.emit(Alert(ts, self.name, "PORT_SCAN_HORIZONTAL", "MEDIUM",
                            f"{src}: {self.cfg['window_sec']}초 안에 {n_hosts}개 호스트의 "
                            f"{p.proto}/{dport} 포트 접근 (sweep)",
                            src, None, {"distinct_hosts": n_hosts, "port": dport}))

    def summary(self) -> dict:
        return {
            f"{s} -> {d}": {"probed_ports": len(self.probed[(s, d)]),
                            "open_ports": sorted(self.open_ports.get((s, d), []))}
            for (s, d) in sorted(self.suspects)
        }
