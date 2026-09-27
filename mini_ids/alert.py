"""[5단계: Alert] 경고 객체와 출력(콘솔 / JSON Lines 로그)."""
from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Optional, TextIO

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
_COLORS = {"LOW": "\033[36m", "MEDIUM": "\033[33m", "HIGH": "\033[31m"}
_RESET = "\033[0m"


@dataclass
class Alert:
    ts: float
    detector: str      # PORTSCAN | ARP | DNS | ICMP | HTTP | SSH
    rule: str          # 예: PORT_SCAN_VERTICAL, ARP_MAPPING_CHANGED
    severity: str      # LOW | MEDIUM | HIGH
    message: str
    src: Optional[str] = None
    dst: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AlertSink:
    """경고를 화면에 출력하고, 선택적으로 JSON Lines 파일에 저장한다."""

    def __init__(self, log_path: Optional[str] = None, quiet: bool = False,
                 color: bool = True, stream: TextIO = sys.stdout):
        self.alerts: list[Alert] = []
        self.quiet = quiet
        self.color = color and stream.isatty()
        self.stream = stream
        self._fp = open(log_path, "a", encoding="utf-8") if log_path else None

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if self._fp:
            self._fp.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")
            self._fp.flush()
        if not self.quiet:
            t = time.strftime("%H:%M:%S", time.localtime(alert.ts))
            sev = f"{alert.severity:<6}"
            if self.color:
                sev = _COLORS[alert.severity] + sev + _RESET
            print(f"[{t}] [ALERT] {sev} {alert.rule:<26} {alert.message}", file=self.stream)

    def close(self) -> None:
        if self._fp:
            self._fp.close()
