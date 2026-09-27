| 시나리오 | 정답 | default | tuned | 울린 규칙(tuned) |
|---|---|---|---|---|
| S01_normal_office | benign | TN | TN | - |
| S02_syn_scan | attack | TP | TP | PORT_SCAN_VERTICAL |
| S03_stealth_scan | attack | TP | TP | PORT_SCAN_VERTICAL, STEALTH_SCAN_PACKET |
| S04_udp_scan | attack | TP | TP | PORT_SCAN_VERTICAL |
| S05_ssh_sweep | attack | TP | TP | PORT_SCAN_HORIZONTAL |
| S06_slow_scan | attack | FN | FN | - |
| S07_monitoring_healthcheck | benign | FP | TN | - |
| S08_arp_spoofing | attack | TP | TP | ARP_MAPPING_CHANGED, ARP_REINFECTION, ARP_REPLY_FLOOD |
| S09_arp_spoof_before_ids | attack | TP | TP | ARP_MAPPING_CHANGED, ARP_REINFECTION, ARP_REPLY_FLOOD |
| S10_router_failover | benign | FP | TN | - |
| S11_dhcp_reassign | benign | FP | FP | ARP_MAPPING_CHANGED |
| S12_dns_tunnel | attack | TP | TP | DNS_SUBDOMAIN_BURST, DNS_TUNNEL_SUSPECT |
| S13_dns_blocklist | attack | FN | TP | DNS_BLOCKLIST |
| S14_icmp_flood | attack | TP | TP | ICMP_FLOOD |
| S15_ping_sweep | attack | TP | TP | ICMP_PING_SWEEP |
| S16_icmp_tunnel | attack | TP | TP | ICMP_LARGE_PAYLOAD |
| S17_http_attacks | attack | TP | TP | HTTP_ATTACK_PATTERN, HTTP_SCANNER_UA |
| S18_http_plain_login | attack | TP | TP | HTTP_PLAINTEXT_CREDENTIAL |
| S19_https_login | attack | FN | FN | - |
| S20_http_split_segment | attack | FN | FN | - |
| S21_ssh_bruteforce | attack | TP | TP | SSH_BRUTE_FORCE |
| S22_ssh_normal | benign | TN | TN | - |
| S23_ssh_hidden_port | attack | TP | TP | SSH_NONSTANDARD_PORT |
| S24_busy_browsing | benign | TN | TN | - |
| S25_av_reputation_dns | benign | FP | TN | - |

- **default**: TP 14 / FN 4 / FP 4 / TN 3 → 탐지율 77.8%, 오탐률 57.1%, 정밀도 77.8%
- **tuned**: TP 15 / FN 3 / FP 1 / TN 6 → 탐지율 83.3%, 오탐률 14.3%, 정밀도 93.8%
