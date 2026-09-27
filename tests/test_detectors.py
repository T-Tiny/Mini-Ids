"""탐지 규칙 단위 테스트:  python3 -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from mini_ids.alert import AlertSink  # noqa: E402
from mini_ids.config import load_config  # noqa: E402
from mini_ids.detectors.base import Cooldown, SlidingWindow  # noqa: E402
from mini_ids.engine import MiniIDS  # noqa: E402

GW, GW_MAC = "192.168.10.1", "02:00:00:aa:aa:aa"
A, A_MAC = "192.168.10.2", "02:00:00:bb:bb:bb"
ATK, ATK_MAC = "192.168.10.3", "02:00:00:cc:cc:cc"


def at(pkt, t):
    pkt.time = t
    return pkt


def new_ids(**override):
    import io
    return MiniIDS(load_config(override=override), AlertSink(stream=io.StringIO()))


def rules(ids):
    return [a.rule for a in ids.sink.alerts]


class TestBase(unittest.TestCase):
    def test_sliding_window_expires_old_entries(self):
        w = SlidingWindow(10)
        for i in range(5):
            w.add("k", i, i)
        w.add("k", 20, 99)             # 20초 시점 → 0~4초 항목은 만료
        self.assertEqual(w.count("k"), 1)

    def test_cooldown(self):
        c = Cooldown(30)
        self.assertTrue(c.ready("x", 0))
        self.assertFalse(c.ready("x", 10))
        self.assertTrue(c.ready("x", 31))


class TestPortScan(unittest.TestCase):
    def syn(self, port, t, flags="S"):
        return at(Ether() / IP(src=ATK, dst="192.168.10.20") / TCP(sport=5555, dport=port, flags=flags), t)

    def test_vertical_scan_detected_at_threshold(self):
        ids = new_ids()
        ids.run(self.syn(p, 0.1 * p) for p in range(1, 20))
        self.assertEqual(rules(ids), [])                       # 19개 → 아직 아님
        ids.process(self.syn(20, 2.0))
        self.assertEqual(rules(ids), ["PORT_SCAN_VERTICAL"])   # 20개 → 탐지

    def test_slow_scan_is_missed(self):                         # 알려진 FN
        ids = new_ids()
        ids.run(self.syn(p, 3.0 * p) for p in range(1, 60))
        self.assertNotIn("PORT_SCAN_VERTICAL", rules(ids))

    def test_xmas_packet_is_signature(self):
        ids = new_ids()
        ids.process(self.syn(80, 0, flags="FPU"))
        self.assertEqual(rules(ids), ["STEALTH_SCAN_PACKET"])

    def test_dns_responses_are_not_udp_scan(self):              # 53 → 임의 포트 응답 30개
        ids = new_ids()
        ids.run(at(Ether() / IP(src="198.51.100.53", dst=A) / UDP(sport=53, dport=30000 + i), i * 0.1)
                for i in range(30))
        self.assertEqual(rules(ids), [])

    def test_whitelist(self):
        ids = new_ids(portscan={"whitelist_src": [ATK]})
        ids.run(self.syn(p, 0.01 * p) for p in range(1, 100))
        self.assertEqual(rules(ids), [])


class TestArp(unittest.TestCase):
    def reply(self, ip, mac, dst, dmac, t, eth=None):
        return at(Ether(src=eth or mac, dst=dmac) / ARP(op=2, psrc=ip, hwsrc=mac, pdst=dst, hwdst=dmac), t)

    def request(self, ip, mac, target, t):
        return at(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=ip, hwsrc=mac, pdst=target), t)

    def test_gateway_mac_change(self):
        ids = new_ids(arp={"protected_ips": [GW]})
        ids.process(self.request(ATK, ATK_MAC, GW, 0))           # 공격자 MAC 학습
        ids.process(self.request(A, A_MAC, GW, 1))
        ids.process(self.reply(GW, GW_MAC, A, A_MAC, 1.001))     # 게이트웨이 정상 학습
        ids.process(self.reply(GW, ATK_MAC, A, A_MAC, 5))        # 위조
        a = ids.sink.alerts[-1]
        self.assertEqual(a.rule, "ARP_MAPPING_CHANGED")
        self.assertEqual(a.severity, "HIGH")
        self.assertEqual(a.details["attacker_ip_candidates"], [ATK])

    def test_allowed_redundant_mac(self):
        ids = new_ids(arp={"allowed_macs": {GW: ["02:00:00:aa:aa:ab"]}})
        ids.process(self.reply(GW, GW_MAC, A, A_MAC, 0))
        ids.process(self.reply(GW, "02:00:00:aa:aa:ab", A, A_MAC, 5))
        self.assertEqual(rules(ids), [])

    def test_arp_probe_ignored(self):
        ids = new_ids()
        ids.process(self.request("0.0.0.0", ATK_MAC, GW, 0))
        self.assertEqual(ids.detectors[1].trusted, {})

    def test_eth_mismatch(self):
        ids = new_ids()
        ids.process(self.reply(GW, GW_MAC, A, A_MAC, 0, eth=ATK_MAC))
        self.assertIn("ARP_ETH_MISMATCH", rules(ids))

    def test_reinfection_after_recover(self):
        ids = new_ids(arp={"trusted": {GW: GW_MAC}})
        ids.process(self.reply(GW, ATK_MAC, A, A_MAC, 0))        # 감염
        ids.process(self.request(A, A_MAC, GW, 10))
        ids.process(self.reply(GW, GW_MAC, A, A_MAC, 10.01))     # recover
        ids.process(self.reply(GW, ATK_MAC, A, A_MAC, 12))       # 재감염
        self.assertEqual(rules(ids), ["ARP_MAPPING_CHANGED", "ARP_REINFECTION"])

    def test_poisoned_before_start_flood(self):
        ids = new_ids()
        ids.run(self.reply(GW, ATK_MAC, A, A_MAC, t) for t in range(0, 10, 2))
        self.assertIn("ARP_REPLY_FLOOD", rules(ids))
        # 신뢰 철회 후 진짜 게이트웨이를 학습하고, 이후 위조를 올바른 방향으로 잡는다
        ids.process(self.request(A, A_MAC, GW, 20))
        ids.process(self.reply(GW, GW_MAC, A, A_MAC, 20.01))
        ids.process(self.reply(GW, ATK_MAC, A, A_MAC, 22))
        last = ids.sink.alerts[-1]
        self.assertEqual((last.details["old_mac"], last.details["new_mac"]), (GW_MAC, ATK_MAC))


class TestPacketRules(unittest.TestCase):
    def test_dns_blocklist_suffix(self):
        ids = new_ids(dns={"blocklist": ["evil.test"]})
        ids.process(at(Ether() / IP(src=A, dst="8.8.8.8") / UDP(sport=3333, dport=53) /
                       DNS(qd=DNSQR(qname="a.b.evil.test")), 0))
        ids.process(at(Ether() / IP(src=A, dst="8.8.8.8") / UDP(sport=3334, dport=53) /
                       DNS(qd=DNSQR(qname="notevil.test")), 1))
        self.assertEqual(rules(ids), ["DNS_BLOCKLIST"])

    def test_dns_tunnel_long_random_label(self):
        ids = new_ids()
        q = "mzxw6ytboi4dsnrtgq3tcmrvhe2dmobqgu4tsnzrk7pw2vlqa5.x.tunnel.test"  # label 50자
        ids.process(at(Ether() / IP(src=A, dst="8.8.8.8") / UDP(sport=3333, dport=53) / DNS(qd=DNSQR(qname=q)), 0))
        self.assertEqual(rules(ids), ["DNS_TUNNEL_SUSPECT"])

    def test_icmp_flood_counts_per_destination(self):
        ids = new_ids()
        ids.run(at(Ether() / IP(src=f"10.0.0.{i % 40}", dst=A) / ICMP(type=8), i * 0.01) for i in range(60))
        self.assertIn("ICMP_FLOOD", rules(ids))                  # 출발지 40개짜리 분산 flood

    def test_icmp_large_payload(self):
        ids = new_ids()
        ids.process(at(Ether() / IP(src=A, dst=GW) / ICMP(type=8) / Raw(b"x" * 1400), 0))
        self.assertEqual(rules(ids), ["ICMP_LARGE_PAYLOAD"])

    def http(self, payload, t=0):
        return at(Ether() / IP(src=ATK, dst=A) / TCP(sport=4444, dport=80, flags="PA") / Raw(payload), t)

    def test_http_url_encoded_sqli(self):
        ids = new_ids()
        ids.process(self.http(b"GET /?id=1%27%20UNION%20SELECT%201-- HTTP/1.1\r\nHost: a\r\n\r\n"))
        self.assertEqual(ids.sink.alerts[0].details["category"], "SQL_INJECTION")

    def test_http_plaintext_password(self):
        ids = new_ids()
        ids.process(self.http(b"POST /login HTTP/1.1\r\nHost: a\r\n\r\nid=a&password=b"))
        self.assertEqual(rules(ids), ["HTTP_PLAINTEXT_CREDENTIAL"])

    def test_http_normal_request_clean(self):
        ids = new_ids()
        ids.process(self.http(b"GET /index.html HTTP/1.1\r\nHost: a\r\nUser-Agent: Mozilla/5.0\r\n\r\n"))
        self.assertEqual(rules(ids), [])

    def test_ssh_bruteforce(self):
        ids = new_ids()
        ids.run(at(Ether() / IP(src=ATK, dst=A) / TCP(sport=40000 + i, dport=22, flags="S"), i * 2.0)
                for i in range(10))
        self.assertEqual(rules(ids), ["SSH_BRUTE_FORCE"])


if __name__ == "__main__":
    unittest.main()
