"""持续跟读：按位置续读、断线/重启不重不漏、落到已清理区段时显式报错。

位置（position）是一个不透明字符串，语义为“已经读到的最后一条记录序号”：
- 首次跟读用 POSITION_START（=0，即从链头第一条开始）；
- 每次 poll 返回 next_position，下游持久化它；断线/重启后原样传回即可续读；
- 位置之后的记录严格按 seq 升序返回，与真实写入顺序一致；
- 若位置已被保留期清理（位置 seq < 当前锚点 seq），抛 PositionCompacted：
  被清理的那段无法补读，绝不能装作没事继续往下走；
- 位置无法解析抛 PositionInvalid。

并发写入时，每次 poll 在存储锁保护下取快照，顺序与定序顺序一致；
长轮询在“看到尾部”后再复查一次，避免等待窗口内的新记录被漏掉。
返回内容是落盘记录，天然不包含脱敏前原文。
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass

from .models import AuditRecord
from .service import AuditService

# 续读位置：尚未读到任何记录（从链头开始）
POSITION_START = "0"


class FollowError(Exception):
    """跟读相关错误的基类。"""


class PositionInvalid(FollowError):
    """续读位置无法解析。"""


class PositionCompacted(FollowError):
    """续读位置已落入被保留期清理的区段，无法保证不丢——必须显式报错。"""

    def __init__(self, position_seq: int, anchor_seq: int) -> None:
        super().__init__(
            f"续读位置 seq={position_seq} 已被保留期清理（当前最早可读序号 "
            f"{anchor_seq}），无法从该位置保证不丢地续读；请从锚点之后重新开始跟读"
        )
        self.position_seq = position_seq
        self.anchor_seq = anchor_seq


@dataclass(frozen=True)
class FollowBatch:
    """一次跟读拿到的一批记录与下次续读位置。"""

    records: list[AuditRecord]
    next_position: str
    waited: bool  # 本次是否发生了等待（False=直接拿到数据；True=等待后拿到或仍为空）


class FollowReader:
    """按单调序号持续跟读审计记录（内容与查询一样为已脱敏数据）。"""

    def __init__(self, service: AuditService, poll_interval_s: float = 0.05) -> None:
        self._service = service
        self._poll_interval_s = poll_interval_s

    @staticmethod
    def encode_position(after_seq: int) -> str:
        """把“已读到的最后序号”编码为续读位置。"""
        if after_seq < 0:
            raise PositionInvalid("续读位置不能为负数")
        return str(int(after_seq))

    @staticmethod
    def decode_position(position: str) -> int:
        """解析续读位置；无法解析抛 PositionInvalid。"""
        try:
            value = int(position)
        except (TypeError, ValueError) as exc:
            raise PositionInvalid(f"续读位置无法解析: {position!r}") from exc
        if value < 0:
            raise PositionInvalid(f"续读位置不能为负数: {position!r}")
        return value

    def poll(self, position: str = POSITION_START, max_records: int = 100,
             wait_timeout_s: float = 0.0) -> FollowBatch:
        """从 position 之后读一批（seq 升序，最多 max_records 条）。

        wait_timeout_s > 0 时，若暂无新记录则长轮询等待，超时返回空批；
        返回前会在“看到尾部”后复查一次，消除等待窗口的竞态。
        """
        if max_records < 1:
            raise ValueError("max_records 必须 >= 1")
        after_seq = self.decode_position(position)

        snapshot = self._service.records()
        anchor = snapshot[0] if snapshot and snapshot[0].anchor else None
        head_seq = anchor.seq if anchor else 0
        if after_seq < head_seq:
            raise PositionCompacted(after_seq, head_seq)

        batch = [r for r in snapshot if not r.anchor and r.seq > after_seq]
        waited = False
        if not batch and wait_timeout_s > 0:
            deadline = time.monotonic() + wait_timeout_s
            waited = True
            while time.monotonic() < deadline:
                time.sleep(self._poll_interval_s)
                snapshot = self._service.records()
                anchor = snapshot[0] if snapshot and snapshot[0].anchor else None
                head_seq = anchor.seq if anchor else 0
                if after_seq < head_seq:
                    raise PositionCompacted(after_seq, head_seq)
                batch = [r for r in snapshot if not r.anchor and r.seq > after_seq]
                if batch:
                    break

        batch = batch[:max_records]
        next_position = str(batch[-1].seq) if batch else str(after_seq)
        return FollowBatch(records=batch, next_position=next_position, waited=waited)

    def stream(self, position: str = POSITION_START, max_records: int = 100,
               wait_timeout_s: float = 1.0) -> Iterator[FollowBatch]:
        """持续跟读生成器：逐批产出新记录，调用方在需要时自行中断即可。"""
        current = position
        while True:
            batch = self.poll(current, max_records=max_records,
                              wait_timeout_s=wait_timeout_s)
            yield batch
            current = batch.next_position
