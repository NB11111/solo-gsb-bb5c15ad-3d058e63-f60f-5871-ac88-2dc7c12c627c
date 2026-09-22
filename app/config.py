"""运行期配置，全部可通过环境变量覆盖。"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("BIDI_DB_PATH", "/data/audits.db")
    # UAX #9 规定显式格式 / 隔离嵌套深度上限为 63；这里取 60 留余量，可配置。
    max_depth: int = int(os.getenv("BIDI_MAX_DEPTH", "60"))


settings = Settings()
