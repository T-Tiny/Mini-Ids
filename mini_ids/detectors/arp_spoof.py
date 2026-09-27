"""ARP Spoofing 탐지 — "IP-MAC 매핑 변화 감지".

슬라이드의 핵심 문장: "좋은 탐지는 현재 패킷 + 이전 상태를 함께 본다."
→ IDS 가 스스로 ARP Table(신뢰 매핑)을 들고 있다가, 새 ARP 패킷의 Sender IP/Sender MAC 과 비교한다.

탐지 기준
  1) ARP_MAPPING_CHANGED : 이미 알고 있는 IP 가 다른 MAC 으로 나타남 (보호 IP=게이트웨이면 HIGH)
                           + 그 MAC 이 원래 누구의 MAC 인지 찾아서 공격자 후보로 표시
  2) ARP_REINFECTION     : 정상 MAC 으로 recover 된 뒤 다시 위조 MAC 으로 바뀜 (감염 반복)
  3) ARP_REPLY_FLOOD     : 요청(Request) 없이 온 Reply 가 같은 내용으로 짧은 시간에 반복
                           → IDS 가 켜지기 전부터 감염 중이라 '이전 상태'가 없어도 잡기 위한 규칙
  4) ARP_ETH_MISMATCH    : Ethernet 헤더의 Src MAC ≠ ARP 의 Sender MAC (위조 도구의 흔적)
  5) ARP_DUPLICATE_MAC   : 이미 다른 IP 의 주인인 MAC 이 보호 IP(게이트웨이)를 자기 것이라고 주장

오탐 완화
  - allowed_macs : 라우터 이중화(VRRP/HSRP), 가상 MAC 등 한 IP 에 허용된 여러 MAC
  - trusted      : 게이트웨이 정적 등록 (Static ARP 와 같은 발상)
"""
from __future__ import annotations

from collections import defaultdict

from ..alert import Alert
from ..parse import PacketInfo
from .base import Cooldown, Detector, SlidingWindow


class ArpSpoofDetector(Detector):
    name = "ARP"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.trusted: dict[str, str] = {ip: m.lower() for ip, m in cfg.get("trusted", {}).items()}
        self.static = set(self.trusted)                      # 설정 파일로 등록된 IP
        self.allowed = {ip: {m.lower() for m in ms} for ip, ms in cfg.get("allowed_macs", {}).items()}
        self.protected = set(cfg.get("protected_ips", [])) | self.static
        self.current: dict[str, str] = dict(self.trusted)    # 지금 네트워크에 보이는 매핑
        self.mac_owner: dict[str, set[str]] = defaultdict(set)
        for ip, m in self.trusted.items():
            self.mac_owner[m].add(ip)
        self.requests: dict[tuple[str, str], float] = {}     # (묻는 IP, 찾는 IP) -> 시각
        self.unsolicited = SlidingWindow(cfg["flood_window_sec"])
        self.cool = Cooldown(cfg["cooldown_sec"])
        self.infections: dict[str, int] = defaultdict(int)
        self.recoveries: dict[str, int] = defaultdict(int)
        self.timeline: list[tuple[float, str, str, str]] = []  # (ts, ip, mac, event)
        self.suspicious: set[tuple[str, str]] = set()          # 위조로 판명된 (IP, MAC) → 다시 학습 금지

    # ------------------------------------------------------------------
    def handle(self, p: PacketInfo) -> None:
        if p.proto != "ARP" or not p.arp_psrc or p.arp_psrc == "0.0.0.0":
            return  # 0.0.0.0 은 ARP Probe(주소 충돌 확인) → 매핑 정보 없음

        ip, mac, ts = p.arp_psrc, p.arp_hwsrc, p.ts
        sev = "HIGH" if ip in self.protected else "MEDIUM"

        # 규칙 4: L2 헤더와 ARP 본문의 MAC 불일치
        if p.src_mac and p.src_mac != mac and self.cool.ready(("eth", p.src_mac, mac), ts):
            self.emit(Alert(ts, self.name, "ARP_ETH_MISMATCH", "MEDIUM",
                            f"Ethernet Src {p.src_mac} ≠ ARP Sender MAC {mac} (Sender IP {ip})",
                            ip, p.arp_pdst, {"eth_src": p.src_mac, "arp_hwsrc": mac}))

        if p.arp_op == 1:                                    # Request 기억
            self.requests[(ip, p.arp_pdst)] = ts
        elif p.arp_op == 2:                                  # Reply: 요청이 있었나?
            req_ts = self.requests.get((p.arp_pdst, ip))
            if req_ts is None or ts - req_ts > self.cfg["request_timeout_sec"]:
                if self._check_flood(p, sev):     # 위조로 판명 → 이 패킷으로는 학습하지 않음
                    self.current[ip] = mac
                    return

        self._check_mapping(ip, mac, ts, sev, p)

    # ------------------------------------------------------------------
    def _check_flood(self, p: PacketInfo, sev: str) -> bool:
        """요청 없는 Reply 반복 검사. 학습된 매핑을 철회했으면 True."""
        key = (p.arp_psrc, p.arp_hwsrc)
        self.unsolicited.add(key, p.ts, p.arp_pdst)
        n = self.unsolicited.count(key)
        distrusted = False
        legit = p.arp_hwsrc in self.allowed.get(p.arp_psrc, ()) or \
            (p.arp_psrc in self.static and self.trusted[p.arp_psrc] == p.arp_hwsrc)
        if n >= self.cfg["flood_threshold"] and not legit and self.cool.ready(("flood",) + key, p.ts):
            # 학습으로 믿게 된 매핑이 사실 위조 반복이었다면 신뢰를 철회 → 다음 정상 응답을 새로 학습
            if self.trusted.get(p.arp_psrc) == p.arp_hwsrc and p.arp_psrc not in self.static:
                del self.trusted[p.arp_psrc]
                self.mac_owner[p.arp_hwsrc].discard(p.arp_psrc)
                self.timeline.append((p.ts, p.arp_psrc, p.arp_hwsrc, "distrust"))
                self.suspicious.add(key)
                distrusted = True
            self.emit(Alert(p.ts, self.name, "ARP_REPLY_FLOOD", sev,
                            f"요청 없는 ARP Reply 반복: '{p.arp_psrc} is-at {p.arp_hwsrc}' "
                            f"{self.cfg['flood_window_sec']}초 동안 {n}회 → {', '.join(sorted(set(self.unsolicited.values(key))))}",
                            p.arp_hwsrc, p.arp_pdst, {"count": n, "victims": sorted(set(self.unsolicited.values(key)))}))
        return distrusted

    def _check_mapping(self, ip: str, mac: str, ts: float, sev: str, p: PacketInfo) -> None:
        if mac in self.allowed.get(ip, ()):                  # 허용된 이중화 MAC
            self.current[ip] = mac
            return

        known = self.trusted.get(ip)
        if known is None and (ip, mac) in self.suspicious:   # 위조로 판명된 매핑은 학습 금지
            self.current[ip] = mac
            return
        if known is None:                                    # 처음 보는 IP → 학습
            others = self.mac_owner.get(mac, set()) - {ip}
            if others and (ip in self.protected or others & self.protected) \
                    and self.cool.ready(("dup", ip, mac), ts):
                self.emit(Alert(ts, self.name, "ARP_DUPLICATE_MAC", sev,
                                f"{mac} 는 이미 {', '.join(sorted(others))} 의 MAC 인데 {ip} 도 자기 것이라고 주장",
                                mac, ip, {"claimed_ip": ip, "also_owns": sorted(others)}))
                self.current[ip] = mac
                return                                       # 의심 매핑은 학습하지 않는다
            self.trusted[ip] = mac
            self.current[ip] = mac
            self.mac_owner[mac].add(ip)
            self.timeline.append((ts, ip, mac, "learn"))
            return

        prev = self.current.get(ip, known)
        if mac == known:                                     # 정상 MAC
            if prev != known:
                self.recoveries[ip] += 1
                self.timeline.append((ts, ip, mac, "recover"))
            self.current[ip] = mac
            return

        # ---- 여기부터 mac != known : 매핑이 바뀌었다 ----
        attacker_of = sorted(self.mac_owner.get(mac, set()) - {ip})
        who = f" (이 MAC 의 원래 주인: {', '.join(attacker_of)})" if attacker_of else ""
        details = {"ip": ip, "old_mac": known, "new_mac": mac, "attacker_ip_candidates": attacker_of,
                   "arp_op": "reply" if p.arp_op == 2 else "request", "victim": p.arp_pdst}

        if prev != mac:                                      # 정상 → 위조 전환 시점
            self.infections[ip] += 1
            self.timeline.append((ts, ip, mac, "infect"))
            if self.infections[ip] >= 2 and self.recoveries[ip] >= 1:
                self.emit(Alert(ts, self.name, "ARP_REINFECTION", sev,
                                f"{ip} 매핑이 recover 후 다시 {mac} 로 변경 ({self.infections[ip]}번째 감염){who}",
                                mac, ip, {**details, "infections": self.infections[ip],
                                          "recoveries": self.recoveries[ip]}))
                self.current[ip] = mac
                self.cool.touch(("chg", ip, mac), ts)
                return

        self.current[ip] = mac
        if self.cool.ready(("chg", ip, mac), ts):
            label = "게이트웨이/보호 IP " if ip in self.protected else ""
            self.emit(Alert(ts, self.name, "ARP_MAPPING_CHANGED", sev,
                            f"{label}{ip} 의 MAC 변경: {known} → {mac}{who}",
                            mac, ip, details))

    def summary(self) -> dict:
        poisoned = {ip: {"trusted": self.trusted.get(ip), "now": m}
                    for ip, m in self.current.items() if self.trusted.get(ip) not in (None, m)
                    and m not in self.allowed.get(ip, ())}
        return {
            "learned_mappings": len(self.trusted),
            "currently_poisoned": poisoned,
            "infections": dict(self.infections),
            "recoveries": dict(self.recoveries),
        }
