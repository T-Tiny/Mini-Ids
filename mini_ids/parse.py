"""[2단계: Parse] Scapy 패킷에서 탐지에 필요한 필드만 뽑아 PacketInfo 로 정리한다.

탐지기(detector)는 Scapy 객체를 직접 뒤지지 않고 이 구조체만 본다.
→ 탐지 로직과 패킷 파싱이 분리되어 테스트와 확장이 쉬워진다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw


@dataclass
class PacketInfo:
    ts: float                      # 캡처 시각 (pcap 재생 시에도 원래 시각 사용)
    length: int = 0
    # L2
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    # ARP
    arp_op: Optional[int] = None   # 1 = who-has(request), 2 = is-at(reply)
    arp_psrc: Optional[str] = None     # Sender IP
    arp_hwsrc: Optional[str] = None    # Sender MAC
    arp_pdst: Optional[str] = None     # Target IP
    arp_hwdst: Optional[str] = None    # Target MAC
    # L3
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    proto: Optional[str] = None    # "TCP" | "UDP" | "ICMP" | "ARP" | None
    # L4
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: str = ""            # Scapy 표기: S, A, F, R, P, U ...
    icmp_type: Optional[int] = None
    # L7
    dns_qname: Optional[str] = None
    dns_is_response: bool = False
    payload: bytes = field(default=b"", repr=False)


def parse(pkt) -> PacketInfo:
    info = PacketInfo(ts=float(pkt.time), length=len(pkt))

    if Ether in pkt:
        info.src_mac = (pkt[Ether].src or "").lower() or None
        info.dst_mac = (pkt[Ether].dst or "").lower() or None

    if ARP in pkt:
        a = pkt[ARP]
        info.proto = "ARP"
        info.arp_op = int(a.op)
        info.arp_psrc = a.psrc
        info.arp_hwsrc = (a.hwsrc or "").lower()
        info.arp_pdst = a.pdst
        info.arp_hwdst = (a.hwdst or "").lower()
        return info

    if IP not in pkt:
        return info

    info.src_ip = pkt[IP].src
    info.dst_ip = pkt[IP].dst

    if TCP in pkt:
        info.proto = "TCP"
        info.sport = int(pkt[TCP].sport)
        info.dport = int(pkt[TCP].dport)
        info.tcp_flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        info.proto = "UDP"
        info.sport = int(pkt[UDP].sport)
        info.dport = int(pkt[UDP].dport)
    elif ICMP in pkt:
        info.proto = "ICMP"
        info.icmp_type = int(pkt[ICMP].type)

    if DNS in pkt and pkt[DNS].qd is not None and DNSQR in pkt:
        info.dns_is_response = bool(pkt[DNS].qr)
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors="ignore")
        info.dns_qname = qname.rstrip(".").lower()

    if Raw in pkt:
        info.payload = bytes(pkt[Raw].load)

    return info
