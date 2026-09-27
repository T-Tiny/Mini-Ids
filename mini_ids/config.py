"""탐지 임계값과 화이트리스트. config.json 으로 덮어쓸 수 있다."""
from __future__ import annotations

import copy
import json
from typing import Optional

DEFAULT_CONFIG: dict = {
    "portscan": {
        "enabled": True,
        "window_sec": 10,           # 관찰 창
        "port_threshold": 20,       # 창 안에서 한 목적지의 서로 다른 포트 N개 이상 → 수직 스캔
        "host_threshold": 15,       # 창 안에서 같은 포트로 서로 다른 호스트 N개 이상 → 수평 스캔(sweep)
        "cooldown_sec": 30,         # 같은 공격자에 대한 중복 경고 억제
        "whitelist_src": [],        # 취약점 스캐너 등 허용된 스캔 출발지
    },
    "arp": {
        "enabled": True,
        # 신뢰 매핑(정적 등록). 게이트웨이는 여기에 넣어두면 IDS 시작 전 감염도 잡는다.
        "trusted": {},              # {"192.168.10.1": "02:00:00:aa:aa:aa"}
        # 한 IP 에 정상적으로 여러 MAC 이 올 수 있는 경우(라우터 이중화, VRRP 등)
        "allowed_macs": {},         # {"192.168.10.1": ["00:00:5e:00:01:01", ...]}
        "protected_ips": [],        # 게이트웨이 등 중요 IP → HIGH 등급
        "request_timeout_sec": 5,   # 요청 없이 온 Reply 판정 기준
        "flood_window_sec": 10,
        "flood_threshold": 5,       # 같은 위조 Reply 반복 횟수
        "cooldown_sec": 30,
    },
    "dns": {
        "enabled": True,
        "blocklist": [],            # 접근 금지 도메인(서브도메인 포함)
        "allow_domains": [],        # 터널링/폭증 검사 예외 도메인 (백신 평판 조회 등)
        "max_qname_len": 60,
        "max_label_len": 40,
        "entropy_threshold": 3.8,   # 긴 label 의 섀넌 엔트로피 (무작위 문자열 판단)
        "rate_window_sec": 10,
        "rate_threshold": 100,      # 한 출발지의 DNS 질의 수 (40 → S24 오탐으로 100 으로 조정)
        "subdomain_threshold": 15,  # 같은 상위 도메인의 서로 다른 서브도메인 수 (터널링)
        "cooldown_sec": 30,
    },
    "icmp": {
        "enabled": True,
        "flood_window_sec": 5,
        "flood_threshold": 50,      # Echo Request 수
        "sweep_window_sec": 10,
        "sweep_threshold": 10,      # 서로 다른 목적지 수 (Ping Sweep)
        "max_payload": 1000,        # 비정상적으로 큰 ICMP payload (터널링/공격 의심)
        "cooldown_sec": 30,
    },
    "http": {
        "enabled": True,
        "credential_patterns": ["password=", "passwd=", "pwd=", "pass=", "authorization: basic"],
        "attack_patterns": {
            "SQL_INJECTION": ["union select", "' or '1'='1", "or 1=1", "sleep(", "information_schema"],
            "PATH_TRAVERSAL": ["../", "..%2f", "/etc/passwd", "win.ini"],
            "XSS": ["<script", "javascript:", "onerror="],
            "CMD_INJECTION": [";cat ", "|id", "`id`", "$(", "cmd.exe"],
        },
        "scanner_user_agents": ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster"],
        "cooldown_sec": 5,
    },
    "ssh": {
        "enabled": True,
        "port": 22,
        "window_sec": 60,
        "attempt_threshold": 10,    # 창 안에서 새 연결(SYN) 시도 수
        "cooldown_sec": 60,
    },
}


def _merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict) and k not in ("trusted", "allowed_macs", "attack_patterns"):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: Optional[str] = None, override: Optional[dict] = None) -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path:
        with open(path, encoding="utf-8") as f:
            _merge(cfg, json.load(f))
    if override:
        _merge(cfg, override)
    return cfg
