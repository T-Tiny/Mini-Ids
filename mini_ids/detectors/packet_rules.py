"""특정 패킷 탐지 — "DNS / ICMP / HTTP / SSH 조건 탐지".

2주차에서 읽었던 필드(packet[DNSQR].qname, packet[ICMP].type, packet[Raw].load, packet[TCP].dport)를
그대로 조건문에 넣은 것. 시그니처(패턴) 규칙과 이상(빈도) 규칙을 섞어 사용한다.

DNS  : 차단 도메인 질의 / 비정상적으로 긴·무작위 서브도메인(터널링) / 한 도메인의 서브도메인 폭증 / 질의 폭증
ICMP : Echo Request 폭증(Flood) / 여러 호스트 Ping Sweep / 비정상적으로 큰 payload
HTTP : 평문 인증 정보(password=, Basic 인증) / 공격 문자열(SQLi, Traversal, XSS, CMDi) / 스캐너 User-Agent
SSH  : 짧은 시간 반복 접속 시도(Brute Force) / 22번이 아닌 포트의 SSH 배너
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import unquote_plus

from ..alert import Alert
from ..parse import PacketInfo
from .base import Cooldown, Detector, SlidingWindow

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def base_domain(qname: str) -> str:
    parts = qname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


# ----------------------------------------------------------------------------- DNS
class DnsDetector(Detector):
    name = "DNS"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.blocklist = [d.lower().rstrip(".") for d in cfg.get("blocklist", [])]
        self.allow = [d.lower().rstrip(".") for d in cfg.get("allow_domains", [])]  # 터널링 검사 예외
        self.rate = SlidingWindow(cfg["rate_window_sec"])
        self.subs = SlidingWindow(cfg["rate_window_sec"])
        self.cool = Cooldown(cfg["cooldown_sec"])
        self.queries = 0

    def handle(self, p: PacketInfo) -> None:
        if not p.dns_qname or p.dns_is_response:
            return
        self.queries += 1
        q, src, ts = p.dns_qname, p.src_ip, p.ts
        trusted_domain = any(q == d or q.endswith("." + d) for d in self.allow)

        for bad in self.blocklist:
            if q == bad or q.endswith("." + bad):
                if self.cool.ready(("block", src, q), ts):
                    self.emit(Alert(ts, self.name, "DNS_BLOCKLIST", "HIGH",
                                    f"{src} 가 차단 도메인 질의: {q}", src, p.dst_ip,
                                    {"qname": q, "matched": bad}))
                break

        if trusted_domain:          # 백신 평판 조회처럼 원래 긴 서브도메인을 쓰는 정상 서비스
            return
        labels = q.split(".")
        longest = max(labels, key=len)
        ent = shannon_entropy(longest)
        if (len(q) > self.cfg["max_qname_len"] or
                (len(longest) > self.cfg["max_label_len"] and ent >= self.cfg["entropy_threshold"])):
            if self.cool.ready(("long", src, base_domain(q)), ts):
                self.emit(Alert(ts, self.name, "DNS_TUNNEL_SUSPECT", "MEDIUM",
                                f"{src} 비정상적으로 긴/무작위 DNS 질의 (길이 {len(q)}, 엔트로피 {ent:.2f}): {q[:70]}…",
                                src, p.dst_ip, {"qname": q, "length": len(q), "entropy": round(ent, 2)}))

        bd = base_domain(q)
        self.subs.add((src, bd), ts, q)
        n_sub = self.subs.distinct((src, bd))
        if n_sub >= self.cfg["subdomain_threshold"] and self.cool.ready(("subs", src, bd), ts):
            self.emit(Alert(ts, self.name, "DNS_SUBDOMAIN_BURST", "MEDIUM",
                            f"{src} 가 {self.cfg['rate_window_sec']}초 동안 {bd} 의 서로 다른 서브도메인 {n_sub}개 질의 (DNS 터널링/DGA 의심)",
                            src, p.dst_ip, {"base_domain": bd, "distinct_subdomains": n_sub}))

        self.rate.add(src, ts)
        n = self.rate.count(src)
        if n >= self.cfg["rate_threshold"] and self.cool.ready(("rate", src), ts):
            self.emit(Alert(ts, self.name, "DNS_QUERY_BURST", "LOW",
                            f"{src} DNS 질의 폭증: {self.cfg['rate_window_sec']}초 동안 {n}회",
                            src, p.dst_ip, {"count": n}))


# ----------------------------------------------------------------------------- ICMP
class IcmpDetector(Detector):
    name = "ICMP"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.flood = SlidingWindow(cfg["flood_window_sec"])
        self.sweep = SlidingWindow(cfg["sweep_window_sec"])
        self.cool = Cooldown(cfg["cooldown_sec"])

    def handle(self, p: PacketInfo) -> None:
        if p.proto != "ICMP":
            return
        src, dst, ts = p.src_ip, p.dst_ip, p.ts

        if len(p.payload) > self.cfg["max_payload"] and self.cool.ready(("big", src), ts):
            self.emit(Alert(ts, self.name, "ICMP_LARGE_PAYLOAD", "MEDIUM",
                            f"{src} → {dst} ICMP type {p.icmp_type} payload {len(p.payload)}바이트 (터널링/비정상 패킷 의심)",
                            src, dst, {"payload_len": len(p.payload), "icmp_type": p.icmp_type}))

        if p.icmp_type != 8:                 # 이하 규칙은 Echo Request 만
            return
        # Flood 는 '피해자'가 받는 부하 → 목적지 기준으로 센다 (출발지가 여럿인 DDoS 도 포함)
        self.flood.add(dst, ts, src)
        n = self.flood.count(dst)
        if n >= self.cfg["flood_threshold"] and self.cool.ready(("flood", dst), ts):
            srcs = sorted(set(self.flood.values(dst)))
            self.emit(Alert(ts, self.name, "ICMP_FLOOD", "HIGH",
                            f"{dst} 로 Echo Request 폭증: {self.cfg['flood_window_sec']}초 동안 {n}개 "
                            f"(출발지 {len(srcs)}개: {', '.join(srcs[:3])})",
                            srcs[0] if len(srcs) == 1 else None, dst, {"count": n, "sources": srcs[:20]}))

        self.sweep.add(src, ts, dst)
        h = self.sweep.distinct(src)
        if h >= self.cfg["sweep_threshold"] and self.cool.ready(("sweep", src), ts):
            self.emit(Alert(ts, self.name, "ICMP_PING_SWEEP", "MEDIUM",
                            f"{src} Ping Sweep: {self.cfg['sweep_window_sec']}초 동안 {h}개 호스트에 Echo Request",
                            src, None, {"distinct_hosts": h}))


# ----------------------------------------------------------------------------- HTTP
class HttpDetector(Detector):
    name = "HTTP"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.cool = Cooldown(cfg["cooldown_sec"])
        self.requests = 0

    def handle(self, p: PacketInfo) -> None:
        if p.proto != "TCP" or not p.payload:
            return
        # 2주차 방식: GET/POST 등으로 시작하는 평문 요청만 본다.
        # 포트 번호로 거르지 않으므로 8081 같은 비표준 포트의 HTTP 도 검사된다.
        if not p.payload.startswith(HTTP_METHODS):
            return
        self.requests += 1
        raw = p.payload.decode(errors="ignore")
        text = unquote_plus(raw).lower()                     # %27 → ' 처럼 URL 인코딩 해제 후 비교
        first = raw.split("\r\n", 1)[0]
        host = re.search(r"(?im)^host:\s*(\S+)", raw)
        base = {"request_line": first[:120], "host": host.group(1) if host else None, "dport": p.dport}
        src, dst, ts = p.src_ip, p.dst_ip, p.ts

        for cat, pats in self.cfg["attack_patterns"].items():
            hit = next((pt for pt in pats if pt in text), None)
            if hit and self.cool.ready(("atk", src, cat), ts):
                self.emit(Alert(ts, self.name, "HTTP_ATTACK_PATTERN", "HIGH",
                                f"{src} → {dst}:{p.dport} {cat} 패턴 '{hit}' : {first[:80]}",
                                src, dst, {**base, "category": cat, "pattern": hit}))

        cred = next((pt for pt in self.cfg["credential_patterns"] if pt in text), None)
        if cred and self.cool.ready(("cred", src, dst), ts):
            self.emit(Alert(ts, self.name, "HTTP_PLAINTEXT_CREDENTIAL", "MEDIUM",
                            f"{src} → {dst}:{p.dport} 평문 HTTP 로 인증 정보 전송 ('{cred}' 포함)",
                            src, dst, {**base, "pattern": cred}))

        ua = re.search(r"(?im)^user-agent:\s*(.+)$", raw)
        if ua:
            agent = ua.group(1).strip()
            tool = next((t for t in self.cfg["scanner_user_agents"] if t in agent.lower()), None)
            if tool and self.cool.ready(("ua", src, tool), ts):
                self.emit(Alert(ts, self.name, "HTTP_SCANNER_UA", "MEDIUM",
                                f"{src} 자동화 공격 도구 User-Agent: {agent[:60]}",
                                src, dst, {**base, "user_agent": agent, "tool": tool}))


# ----------------------------------------------------------------------------- SSH
class SshDetector(Detector):
    name = "SSH"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.port = cfg["port"]
        self.attempts = SlidingWindow(cfg["window_sec"])
        self.cool = Cooldown(cfg["cooldown_sec"])

    def handle(self, p: PacketInfo) -> None:
        if p.proto != "TCP":
            return
        src, dst, ts = p.src_ip, p.dst_ip, p.ts

        # 새 연결 시도(SYN) 를 센다: 로그인 실패마다 새 TCP 연결을 여는 brute force 도구의 특징
        if p.dport == self.port and "S" in p.tcp_flags and "A" not in p.tcp_flags:
            self.attempts.add((src, dst), ts, p.sport)
            n = self.attempts.count((src, dst))
            if n >= self.cfg["attempt_threshold"] and self.cool.ready(("bf", src, dst), ts):
                self.emit(Alert(ts, self.name, "SSH_BRUTE_FORCE", "HIGH",
                                f"{src} → {dst}:{self.port} {self.cfg['window_sec']}초 동안 SSH 연결 시도 {n}회",
                                src, dst, {"attempts": n}))

        # 22번이 아닌 포트에서 SSH 배너 → 숨겨진 SSH 서버/터널 가능성
        if p.payload.startswith(b"SSH-") and self.port not in (p.sport, p.dport):
            if self.cool.ready(("banner", src, dst), ts):
                banner = p.payload.split(b"\r\n")[0].decode(errors="ignore")
                self.emit(Alert(ts, self.name, "SSH_NONSTANDARD_PORT", "LOW",
                                f"{src}:{p.sport} → {dst}:{p.dport} 비표준 포트 SSH 배너 '{banner}'",
                                src, dst, {"banner": banner, "sport": p.sport, "dport": p.dport}))
