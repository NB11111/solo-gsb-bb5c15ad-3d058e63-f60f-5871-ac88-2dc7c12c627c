"""手工初始化 SQLite 数据库：python init_db.py [数据库路径]"""

from __future__ import annotations

import sys

from app.config import settings
from app.db import init_db

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else settings.db_path
    init_db(path)
    print(f"initialized audit database at {path}")
