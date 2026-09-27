#!/usr/bin/env python3
"""정답(label)이 붙은 테스트 시나리오 PCAP 생성기 (2주차 Packet Crafting + wrpcap 활용).

각 시나리오는 scenarios/*.pcap 으로 저장되고, 정답은 scenarios/manifest.json 에 기록된다.
  label = "attack" → expected_rules 중 하나라도 울리면 탐지 성공(TP), 아니면 FN
  label = "benign" → 경고가 하나라도 나오면 FP, 아니면 TN

주소는 3·4주차 슬라이드(192.168.10.0/24)를 따르고, 외부 호스트는 문서용 예약 대역을 쓴다.
"""
from __future__ import annotations

import base64
import json
import os
import random
import sys

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

random.seed(2026)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scenarios")

# ---------------------------------------------------------------- 등장 인물
GW, GW_MAC = "192.168.10.1", "02:00:00:aa:aa:aa"
GW2_MAC = "02:00:00:aa:aa:ab"                      # 이중화된 대기(standby) 라우터
A, A_MAC = "192.168.10.2", "02:00:00:bb:bb:bb"     # Sender (피해자)
ATK, ATK_MAC = "192.168.10.3", "02:00:00:cc:cc:cc"  # Attacker
SRV, SRV_MAC = "192.168.10.20", "02:00:00:dd:dd:dd"  # 내부 서버
MON, MON_MAC = "192.168.10.30", "02:00:00:ee:ee:ee"  # 모니터링 서버
BCAST = "ff:ff:ff:ff:ff:ff"
DNS_SRV = "198.51.100.53"
WEB = "203.0.113.10"
MAC = {GW: GW_MAC, A: A_MAC, ATK: ATK_MAC, SRV: SRV_MAC, MON: MON_MAC}


def mac_of(ip):
    return MAC.get(ip, GW_MAC)  # 외부 IP 는 게이트웨이 MAC 으로 나간다


class Cap:
    """패킷 목록 + 가상 시계. add(pkt, t) 로 캡처 시각을 지정한다."""

    def __init__(self):
        self.pkts = []

    def add(self, pkt, t):
        pkt.time = t
        self.pkts.append(pkt)

    def l3(self, src, dst, layer, t, src_mac=None, dst_mac=None):
        self.add(Ether(src=src_mac or mac_of(src), dst=dst_mac or mac_of(dst)) / IP(src=src, dst=dst) / layer, t)

    # --- 자주 쓰는 동작 --------------------------------------------------
    def arp_req(self, src, smac, target, t):
        self.add(Ether(src=smac, dst=BCAST) / ARP(op=1, psrc=src, hwsrc=smac, pdst=target), t)

    def arp_rep(self, src, smac, dst, dmac, t, eth_src=None):
        self.add(Ether(src=eth_src or smac, dst=dmac) / ARP(op=2, psrc=src, hwsrc=smac, pdst=dst, hwdst=dmac), t)

    def arp_exchange(self, asker, target, t):
        self.arp_req(asker, MAC[asker], target, t)
        self.arp_rep(target, MAC[target], asker, MAC[asker], t + 0.001)

    def tcp_session(self, c, s, dport, t, data=b"", resp=b"", sport=None):
        sport = sport or random.randint(40000, 60000)
        seq, ack = random.randint(1, 2**31), random.randint(1, 2**31)
        self.l3(c, s, TCP(sport=sport, dport=dport, flags="S", seq=seq), t)
        self.l3(s, c, TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1), t + 0.01)
        self.l3(c, s, TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1), t + 0.02)
        if data:
            self.l3(c, s, TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=ack + 1) / Raw(data), t + 0.03)
        if resp:
            self.l3(s, c, TCP(sport=dport, dport=sport, flags="PA", seq=ack + 1, ack=seq + 1 + len(data)) / Raw(resp), t + 0.05)
        self.l3(c, s, TCP(sport=sport, dport=dport, flags="FA", seq=seq + 1 + len(data), ack=ack + 1 + len(resp)), t + 0.08)
        self.l3(s, c, TCP(sport=dport, dport=sport, flags="FA", seq=ack + 1 + len(resp), ack=seq + 2 + len(data)), t + 0.09)

    def dns(self, c, qname, t, answer="203.0.113.99"):
        sport = random.randint(1024, 65535)
        qid = random.randint(0, 65535)
        self.l3(c, DNS_SRV, UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname)), t)
        self.l3(DNS_SRV, c, UDP(sport=53, dport=sport) /
                DNS(id=qid, qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata=answer)), t + 0.02)

    def ping(self, src, dst, t, seq=1, payload=b"abcdefghijklmnopqrstuvwabcdefghi", reply=True):
        self.l3(src, dst, ICMP(type=8, id=0x1234, seq=seq) / Raw(payload), t)
        if reply:
            self.l3(dst, src, ICMP(type=0, id=0x1234, seq=seq) / Raw(payload), t + 0.005)

    def http_get(self, c, s, path, t, host="www.example.com", ua="Mozilla/5.0", extra=""):
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n{extra}\r\n".encode()
        self.tcp_session(c, s, 80, t, req, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    def background(self, t0, dur, host=A):
        """평범한 사무실 트래픽: ARP, DNS, HTTPS, HTTP, ping, NTP."""
        self.arp_exchange(host, GW, t0)
        sites = ["www.google.com", "news.naver.com", "github.com", "dreamhack.io", "www.youtube.com",
                 "api.github.com", "fonts.googleapis.com", "cdn.jsdelivr.net", "www.wikipedia.org"]
        t = t0 + 0.5
        while t < t0 + dur:
            r = random.random()
            if r < 0.35:
                self.dns(host, random.choice(sites), t)
            elif r < 0.75:
                self.tcp_session(host, WEB, 443, t, os.urandom(random.randint(200, 600)), os.urandom(900))
            elif r < 0.85:
                self.http_get(host, WEB, random.choice(["/", "/index.html", "/news?id=3", "/static/app.js"]), t)
            elif r < 0.92:
                self.ping(host, GW, t, seq=int(t) % 65536)
            else:
                self.l3(host, "203.0.113.123", UDP(sport=random.randint(1024, 65535), dport=123) / Raw(os.urandom(48)), t)
            t += random.uniform(0.3, 1.5)
        if random.random() < 1:  # 주기적 ARP 갱신
            self.arp_exchange(host, GW, t0 + dur * 0.6)

    def save(self, name):
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(os.path.join(OUT, f"{name}.pcap"), self.pkts)
        return len(self.pkts)


# ================================================================ 시나리오
SCENARIOS = []


def scenario(name, label, rules, desc, expect_note=""):
    def deco(fn):
        SCENARIOS.append(dict(name=name, label=label, expected_rules=rules, description=desc,
                              design_note=expect_note, fn=fn))
        return fn
    return deco


T0 = 1790000000.0  # 가상 캡처 시작 시각


@scenario("S01_normal_office", "benign", [], "정상 사무실 트래픽 90초 (DNS 응답의 임의 목적지 포트, HTTPS 다중 연결 포함)")
def s01(c):
    c.background(T0, 90)
    for i in range(30):  # 브라우저가 한 서버의 443 으로 연결 30개를 동시에 여는 상황
        c.tcp_session(A, WEB, 443, T0 + 40 + i * 0.1, os.urandom(300), os.urandom(800))


@scenario("S02_syn_scan", "attack", ["PORT_SCAN_VERTICAL"], "nmap -sS 형태: 1~1024 포트 SYN 스캔 (약 2초)")
def s02(c):
    c.background(T0, 30)
    t = T0 + 10
    for port in range(1, 1025):
        sp = 54321
        c.l3(ATK, SRV, TCP(sport=sp, dport=port, flags="S", seq=1000), t)
        if port in (22, 80, 443):
            c.l3(SRV, ATK, TCP(sport=port, dport=sp, flags="SA", ack=1001), t + 0.001)
            c.l3(ATK, SRV, TCP(sport=sp, dport=port, flags="R"), t + 0.002)
        else:
            c.l3(SRV, ATK, TCP(sport=port, dport=sp, flags="RA", ack=1001), t + 0.001)
        t += 0.002


@scenario("S03_stealth_scan", "attack", ["STEALTH_SCAN_PACKET", "PORT_SCAN_VERTICAL"], "NULL / FIN / XMAS 스캔 각 30포트")
def s03(c):
    c.background(T0, 30)
    t = T0 + 8
    for flags in ("", "F", "FPU"):
        for port in random.sample(range(1, 1024), 30):
            c.l3(ATK, SRV, TCP(sport=40000, dport=port, flags=flags), t)
            t += 0.01
        t += 1


@scenario("S04_udp_scan", "attack", ["PORT_SCAN_VERTICAL"], "UDP 스캔 100포트")
def s04(c):
    c.background(T0, 30)
    t = T0 + 12
    for port in random.sample(range(1, 1024), 100):
        c.l3(ATK, SRV, UDP(sport=45678, dport=port), t)
        c.l3(SRV, ATK, ICMP(type=3, code=3) / IP(src=ATK, dst=SRV) / UDP(sport=45678, dport=port), t + 0.001)
        t += 0.02


@scenario("S05_ssh_sweep", "attack", ["PORT_SCAN_HORIZONTAL"], "수평 스캔: 192.168.10.100~139 의 22번 포트 sweep")
def s05(c):
    c.background(T0, 30)
    t = T0 + 5
    for h in range(100, 140):
        c.l3(ATK, f"192.168.10.{h}", TCP(sport=51000, dport=22, flags="S"), t, dst_mac=f"02:00:00:00:10:{h:02x}")
        t += 0.05


@scenario("S06_slow_scan", "attack", ["PORT_SCAN_VERTICAL"], "느린 스캔(nmap -T1 흉내): 3초에 1포트씩 60포트",
          "임계값(10초/20포트) 회피 → FN 예상")
def s06(c):
    c.background(T0, 190)
    t = T0 + 5
    for port in random.sample(range(1, 1024), 60):
        c.l3(ATK, SRV, TCP(sport=41000, dport=port, flags="S"), t)
        c.l3(SRV, ATK, TCP(sport=port, dport=41000, flags="RA"), t + 0.001)
        t += 3


@scenario("S07_monitoring_healthcheck", "benign", [], "모니터링 서버가 5초 안에 서비스 포트 25개 헬스체크 (Nagios/Zabbix 형태)",
          "정상이지만 '다수 포트 접근' 모양 → FP 예상 (whitelist_src 로 해결 가능)")
def s07(c):
    c.background(T0, 30)
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432,
             5900, 6379, 8080, 8443, 9000, 9200, 11211, 27017]
    t = T0 + 10
    for p in ports:
        c.tcp_session(MON, SRV, p, t)
        t += 0.2


@scenario("S08_arp_spoofing", "attack", ["ARP_MAPPING_CHANGED", "ARP_REINFECTION", "ARP_REPLY_FLOOD"],
          "양방향 ARP Spoofing(infect 반복) + Relay + recover 후 재감염")
def s08(c):
    c.background(T0, 80)
    c.arp_exchange(ATK, GW, T0 + 1)                  # 공격자도 평소엔 정상 호스트 (CC = .3 학습)
    def infect(t):
        c.arp_rep(GW, ATK_MAC, A, A_MAC, t)          # A 에게: "게이트웨이는 CC"
        c.arp_rep(A, ATK_MAC, GW, GW_MAC, t + 0.001)  # GW 에게: "A 는 CC"
    t = T0 + 20
    while t < T0 + 40:                                # 1차 감염: 2초마다 반복
        infect(t)
        # Relay: A → (CC) → GW
        c.add(Ether(src=A_MAC, dst=ATK_MAC) / IP(src=A, dst=WEB) / TCP(sport=50000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), t + 0.5)
        c.add(Ether(src=ATK_MAC, dst=GW_MAC) / IP(src=A, dst=WEB) / TCP(sport=50000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), t + 0.51)
        t += 2
    c.arp_exchange(A, GW, T0 + 45)                    # recover: 정상 응답으로 풀림
    t = T0 + 55
    while t < T0 + 75:                                # 재감염
        infect(t)
        t += 2


@scenario("S09_arp_spoof_before_ids", "attack", ["ARP_REPLY_FLOOD", "ARP_MAPPING_CHANGED", "ARP_REINFECTION"],
          "IDS 시작 전부터 감염 중 (첫 관측 매핑이 이미 위조)",
          "학습형만으로는 '이전 상태'가 없음 → 반복 Reply 규칙/정적 등록으로 보완")
def s09(c):
    t = T0
    while t < T0 + 30:
        c.arp_rep(GW, ATK_MAC, A, A_MAC, t)
        t += 2
    c.background(T0 + 1, 30)


@scenario("S10_router_failover", "benign", [], "라우터 이중화(VRRP) 절체: 게이트웨이 IP 가 standby 라우터 MAC 으로 Gratuitous ARP",
          "기본 설정은 FP, allowed_macs 등록 시 TN 예상")
def s10(c):
    c.background(T0, 60)
    for i in range(3):  # 절체 직후 Gratuitous ARP 3회
        c.add(Ether(src=GW2_MAC, dst=BCAST) / ARP(op=2, psrc=GW, hwsrc=GW2_MAC, pdst=GW, hwdst=BCAST), T0 + 30 + i)


@scenario("S11_dhcp_reassign", "benign", [], "DHCP 재할당: .50 을 쓰던 노트북이 떠나고 새 장비가 같은 IP 사용",
          "정상 변경이지만 IP-MAC 변화 → FP 예상")
def s11(c):
    c.background(T0, 60)
    old, new = "02:00:00:50:50:01", "02:00:00:50:50:02"
    c.add(Ether(src=old, dst=BCAST) / ARP(op=1, psrc="192.168.10.50", hwsrc=old, pdst=GW), T0 + 5)
    c.add(Ether(src=new, dst=BCAST) / ARP(op=1, psrc="0.0.0.0", hwsrc=new, pdst="192.168.10.50"), T0 + 40)  # ARP probe
    c.add(Ether(src=new, dst=BCAST) / ARP(op=1, psrc="192.168.10.50", hwsrc=new, pdst="192.168.10.50"), T0 + 41)  # announce


@scenario("S12_dns_tunnel", "attack", ["DNS_TUNNEL_SUSPECT", "DNS_SUBDOMAIN_BURST"], "DNS 터널링: 데이터를 base32 로 서브도메인에 실어 반복 질의")
def s12(c):
    c.background(T0, 40)
    t = T0 + 10
    secret = os.urandom(600)
    for i in range(0, len(secret), 30):
        chunk = base64.b32encode(secret[i:i + 30]).decode().rstrip("=").lower()
        c.dns(A, f"{chunk}.{i // 30}.t.tunnel-exfil.test", t)
        t += 0.3


@scenario("S13_dns_blocklist", "attack", ["DNS_BLOCKLIST"], "악성코드 C2 도메인 질의 (malware-c2.example)",
          "blocklist 가 설정돼야만 탐지 (기본 설정에선 FN)")
def s13(c):
    c.background(T0, 30)
    for i in range(3):
        c.dns(A, "beacon.malware-c2.example", T0 + 10 + i * 5)


@scenario("S14_icmp_flood", "attack", ["ICMP_FLOOD"], "ICMP Flood: 2초 동안 Echo Request 200개")
def s14(c):
    c.background(T0, 20)
    for i in range(200):
        c.ping(ATK, SRV, T0 + 8 + i * 0.01, seq=i, reply=False)


@scenario("S15_ping_sweep", "attack", ["ICMP_PING_SWEEP"], "Ping Sweep: 192.168.10.1~60 에 Echo Request")
def s15(c):
    c.background(T0, 20)
    for h in range(1, 61):
        c.l3(ATK, f"192.168.10.{h}", ICMP(type=8, id=7, seq=h), T0 + 5 + h * 0.03, dst_mac=BCAST)


@scenario("S16_icmp_tunnel", "attack", ["ICMP_LARGE_PAYLOAD"], "ICMP 터널링: payload 1400바이트 Echo 요청으로 데이터 전송")
def s16(c):
    c.background(T0, 20)
    for i in range(5):
        c.ping(A, "203.0.113.66", T0 + 5 + i, seq=i, payload=os.urandom(1400))


@scenario("S17_http_attacks", "attack", ["HTTP_ATTACK_PATTERN", "HTTP_SCANNER_UA"], "SQLi(URL 인코딩)/Path Traversal/XSS + sqlmap User-Agent")
def s17(c):
    c.background(T0, 30)
    c.http_get(ATK, SRV, "/item.php?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--", T0 + 5,
               ua="sqlmap/1.8#stable (https://sqlmap.org)")
    c.http_get(ATK, SRV, "/download?file=../../../../etc/passwd", T0 + 8)
    c.http_get(ATK, SRV, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", T0 + 11)


@scenario("S18_http_plain_login", "attack", ["HTTP_PLAINTEXT_CREDENTIAL"], "평문 HTTP 로그인 (POST password=) + Basic 인증")
def s18(c):
    c.background(T0, 30)
    body = b"username=casper&password=P%40ssw0rd!"
    req = (b"POST /login HTTP/1.1\r\nHost: intranet.local\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    c.tcp_session(A, SRV, 80, T0 + 10, req, b"HTTP/1.1 302 Found\r\n\r\n")
    c.http_get(A, SRV, "/admin", T0 + 15, extra="Authorization: Basic Y2FzcGVyOnNlY3JldA==\r\n")


@scenario("S19_https_login", "attack", ["HTTP_PLAINTEXT_CREDENTIAL"], "같은 로그인을 HTTPS(TLS)로 전송",
          "암호화되어 payload 검사 불가 → FN 예상 (의도된 한계)")
def s19(c):
    c.background(T0, 30)
    tls = b"\x17\x03\x03\x00\x60" + os.urandom(96)   # TLS Application Data 레코드
    c.tcp_session(A, SRV, 443, T0 + 10, tls, b"\x17\x03\x03\x00\x40" + os.urandom(64))


@scenario("S20_http_split_segment", "attack", ["HTTP_ATTACK_PATTERN"], "SQLi 문자열을 두 TCP 세그먼트로 쪼개 전송",
          "TCP 재조립이 없어 패턴이 잘림 → FN 예상")
def s20(c):
    c.background(T0, 20)
    sp = 47000
    c.l3(ATK, SRV, TCP(sport=sp, dport=80, flags="S", seq=10), T0 + 5)
    c.l3(SRV, ATK, TCP(sport=80, dport=sp, flags="SA", seq=500, ack=11), T0 + 5.01)
    c.l3(ATK, SRV, TCP(sport=sp, dport=80, flags="A", seq=11, ack=501), T0 + 5.02)
    p1 = b"GET /item.php?id=1%20UNI"
    p2 = b"ON%20SEL"
    p3 = b"ECT%20password%20FROM%20users HTTP/1.1\r\nHost: srv\r\n\r\n"
    c.l3(ATK, SRV, TCP(sport=sp, dport=80, flags="PA", seq=11, ack=501) / Raw(p1), T0 + 5.03)
    c.l3(ATK, SRV, TCP(sport=sp, dport=80, flags="PA", seq=11 + len(p1), ack=501) / Raw(p2), T0 + 5.04)
    c.l3(ATK, SRV, TCP(sport=sp, dport=80, flags="PA", seq=11 + len(p1) + len(p2), ack=501) / Raw(p3), T0 + 5.05)


@scenario("S21_ssh_bruteforce", "attack", ["SSH_BRUTE_FORCE"], "SSH Brute Force: 1초 간격으로 40회 접속 시도 (hydra 형태)")
def s21(c):
    c.background(T0, 60)
    for i in range(40):
        c.tcp_session(ATK, SRV, 22, T0 + 10 + i, b"SSH-2.0-libssh_0.9.6\r\n" + os.urandom(200),
                      b"SSH-2.0-OpenSSH_9.6\r\n" + os.urandom(300))


@scenario("S22_ssh_normal", "benign", [], "관리자의 정상 SSH 접속 3회 (1분)")
def s22(c):
    c.background(T0, 60)
    for i in range(3):
        c.tcp_session(A, SRV, 22, T0 + 10 + i * 20, b"SSH-2.0-OpenSSH_9.6\r\n" + os.urandom(500),
                      b"SSH-2.0-OpenSSH_9.6\r\n" + os.urandom(800))


@scenario("S23_ssh_hidden_port", "attack", ["SSH_NONSTANDARD_PORT"], "비표준 포트(4444)에서 SSH 배너 → 백도어/터널 의심")
def s23(c):
    c.background(T0, 20)
    c.tcp_session(A, "203.0.113.200", 4444, T0 + 5, b"SSH-2.0-OpenSSH_8.9\r\n", b"SSH-2.0-dropbear_2022.83\r\n")


@scenario("S24_busy_browsing", "benign", [], "뉴스 사이트 접속: 30초에 도메인 25개 + 같은 CDN 서브도메인 12개 질의")
def s24(c):
    c.background(T0, 30)
    t = T0 + 5
    for i in range(25):
        c.dns(A, f"www.site{i}.com", t)
        t += 0.2
    for i in range(12):
        c.dns(A, f"img{i}.cdn-static.com", t)
        t += 0.1


@scenario("S25_av_reputation_dns", "benign", [], "백신의 DNS 기반 파일 평판 조회 (해시값이 서브도메인에 들어감)",
          "정상이지만 긴 무작위 label → FP 예상 (도메인 화이트리스트 필요)")
def s25(c):
    c.background(T0, 30)
    for i in range(5):
        h = os.urandom(32).hex()
        c.dns(A, f"{h}.v1.avts.av-vendor.example", T0 + 10 + i)


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = []
    only = set(sys.argv[1:])
    for s in SCENARIOS:
        if only and s["name"] not in only:
            continue
        c = Cap()
        s["fn"](c)
        n = c.save(s["name"])
        manifest.append({k: v for k, v in s.items() if k != "fn"} | {"packets": n, "pcap": f"{s['name']}.pcap"})
        print(f"[+] {s['name']:<30} {n:>6} packets  ({s['label']})")
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
