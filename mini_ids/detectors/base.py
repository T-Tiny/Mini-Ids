"""모든 탐지기가 공유하는 도구: 슬라이딩 윈도우, 경고 쿨다운."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Callable, Hashable

from ..alert import Alert
from ..parse import PacketInfo


class SlidingWindow:
    """key 별로 (시각, 값) 을 모아 두고 window 초보다 오래된 것은 버린다.

    예) key=(공격자IP, 피해자IP), 값=목적지 포트
        → distinct(key) 가 '최근 10초 동안 접근한 서로 다른 포트 수'
    """

    def __init__(self, window_sec: float):
        self.window = window_sec
        self._data: dict[Hashable, deque] = defaultdict(deque)

    def add(self, key: Hashable, ts: float, value: Hashable = None) -> None:
        dq = self._data[key]
        dq.append((ts, value))
        self._expire(dq, ts)

    def _expire(self, dq: deque, now: float) -> None:
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

    def count(self, key: Hashable) -> int:
        return len(self._data.get(key, ()))

    def distinct(self, key: Hashable) -> int:
        return len({v for _, v in self._data.get(key, ())})

    def values(self, key: Hashable) -> list:
        return [v for _, v in self._data.get(key, ())]


class Cooldown:
    """같은 key 에 대해 cooldown 초 안에는 경고를 한 번만 낸다 (경고 폭주 방지)."""

    def __init__(self, cooldown_sec: float):
        self.cooldown = cooldown_sec
        self._last: dict[Hashable, float] = {}

    def ready(self, key: Hashable, ts: float) -> bool:
        last = self._last.get(key)
        if last is not None and ts - last < self.cooldown:
            return False
        self._last[key] = ts
        return True

    def touch(self, key: Hashable, ts: float) -> None:
        """다른 경고를 냈을 때 이 key 의 쿨다운도 새로 시작시킨다."""
        self._last[key] = ts


class Detector:
    name = "BASE"

    def __init__(self, cfg: dict, emit: Callable[[Alert], None]):
        self.cfg = cfg
        self.emit = emit

    def handle(self, p: PacketInfo) -> None:  # pragma: no cover - 인터페이스
        raise NotImplementedError

    def summary(self) -> dict:
        return {}
