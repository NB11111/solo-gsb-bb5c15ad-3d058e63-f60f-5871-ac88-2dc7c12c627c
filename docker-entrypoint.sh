#!/bin/sh
set -e

# 初始化 SQLite 表结构（幂等），然后执行主进程命令
echo "[entrypoint] initializing database at ${BIDI_DB_PATH:-/data/audits.db}"
python init_db.py

exec "$@"
