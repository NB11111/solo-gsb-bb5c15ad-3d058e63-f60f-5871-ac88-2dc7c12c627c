# Unicode 双向文本安全审计 API

基于 **FastAPI + SQLite + Docker** 的服务，用于检测文本中的 Unicode 双向
（bidirectional）控制字符——即 [Trojan Source](https://trojansource.codes/)
（CVE-2021-42574）一类攻击所依赖的字符。服务解析控制符的配对与嵌套
关系，报告每个控制符的码点、逻辑索引、影响范围和未闭合错误，并为危险
区段生成**保持可读逻辑顺序的转义预览**。

> 输入文本在任何环节都不会被改写：它按原样存储在 SQLite 中，所有转义
> 结果都只是附带的只读视图。

## 目录结构

```
.
├── app/
│   ├── __init__.py
│   ├── bidi.py          # 核心：UAX #9 显式格式/隔离栈解析与转义预览
│   ├── config.py        # 环境变量配置
│   ├── db.py            # SQLite 访问层
│   ├── main.py          # FastAPI 路由与应用
│   ├── models.py        # Pydantic 请求/响应模型
│   └── schema.sql       # 建表语句
├── tests/
│   ├── test_bidi.py     # 配对/嵌套/段落/溢出等规则测试（19 用例）
│   └── test_api.py      # API 端到端测试
├── init_db.py           # 手工初始化脚本（容器 entrypoint 也调用它）
├── docker-entrypoint.sh # 容器启动前幂等初始化数据库
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── requirements-dev.txt
```

## 审计的字符

| 码点 | 缩写 | 含义 | 默认风险 |
|---|---|---|---|
| U+202A | LRE | 从左至右嵌入 | medium（未闭合/溢出→high） |
| U+202B | RLE | 从右至左嵌入 | medium（未闭合/溢出→high） |
| U+202D | LRO | 从左至右**覆盖** | **high** |
| U+202E | RLO | 从右至左**覆盖**（Trojan Source 主力字符） | **high** |
| U+202C | PDF | 闭合最近的嵌入/覆盖 | 随被闭合对象；stray→high |
| U+2066 | LRI | 从左至右隔离 | medium（未闭合/溢出→high） |
| U+2067 | RLI | 从右至左隔离 | medium（未闭合/溢出→high） |
| U+2068 | FSI | 首强字符隔离（自动判向） | medium（未闭合/溢出→high） |
| U+2069 | PDI | 闭合最近的隔离 | medium；stray→medium |
| U+200E | LRM | 从左至右标记（零宽） | low |
| U+200F | RLM | 从右至右标记（零宽） | low |
| U+061C | ALM | 阿拉伯字母标记（零宽） | low |
| U+200D / U+200C / U+FEFF / U+2060 / U+00AD | ZWJ/ZWNJ/BOM/WJ/SHY | 其它不可见/易混格式字符 | low |

### 配对与嵌套规则（UAX #9 摘要）

* 嵌入/覆盖（LRE/RLE/LRO/RLO）与 PDF 配对；隔离（LRI/RLI/FSI）与 PDI
  配对，二者共享同一个显式格式栈。
* **PDF 不能跨隔离匹配**：栈顶是隔离时 PDF 被忽略并报 stray（规则 X7）。
* **PDI 关闭最近的隔离**，同时自动闭合该隔离之上所有没有 PDF 的嵌入/
  覆盖（X5c/X6a/X6b），这些条目标记 `auto_closed`。
* 控制字符按 UBA 段落分隔符分段：`\n \v \f \r`、NEL(U+0085)、
  U+2028、U+2029。段落结束时栈中仍未闭合的条目报 **unclosed**，
  影响范围延伸到段末，下一段重新计数（X8/X6c）。
* 嵌套深度上限默认 60（UBA 规定 63，可用 `BIDI_MAX_DEPTH` 配置）；
  超限开启符记 `depth_overflow`，无影响范围且按 high 报告。
* FSI 的方向按“首个强类型字符”近似解析为 LRI/RLI（无强字符时按
  RLI），结果体现在 `resolved_abbreviation` / `resolved_base_direction`。

### 整体风险级别

`none`（无任何控制符）/ `low` / `medium` / `high` / `critical`，
取所有发现中的最高级（当前规则下最高为 high；critical 预留给未来的
复合规则）。覆盖符（RLO/LRO）与任何未闭合、溢出、stray 均为 high。

## API

服务启动后监听 **8000** 端口，交互式文档在 <http://localhost:8000/docs>。

### `POST /api/v1/audits`

请求体：

```json
{
  "text": "report\u202ecod.js\u202c.exe",
  "filename": "report\u202ecod.js\u202c.exe"
}
```

* `text`（必填，至少 1 个码点）：待审计原文，原样保存。
* `filename`（可选）：来源文件名；纯空白字符串按未提供处理。

响应（201）核心字段：

* `id` / `filename` / `risk_level` / `text_sha256` / `created_at`
* `report.findings[]`：每个控制符一条记录
  * `code_point`（如 `U+202E`）、`char_name`、`abbreviation`
  * `logical_index`（全文件码点序号）、`paragraph`、`paragraph_offset`
  * `kind`（embedding / override / isolate / implicit_mark / invisible_format）
  * `severity`、`matched`、`unclosed`、`overflow`、`reasons`
  * `influence_span`：**含控制符**的影响范围（半开区间 start/end）
    * `escaped_preview`：控制符转义为 `\u202e` 形式，保持逻辑顺序
    * `named_preview`：控制符转义为 `<RLO>` 形式
    * `raw_preview`：原始逻辑文本（可能被终端重排，仅作对照）
  * `inner_span`：**不含开启/关闭控制符**的内部文本，同样带三种预览
  * `closer`：关闭符的码点、索引、段落，以及 `auto_closed`
  * 覆盖区额外给出 `approx_visual_preview`：把区内可显示字符近似反转，
    直观演示屏幕上看到的顺序（非完整 UBA 渲染）
* `report.dangerous_spans[]`：所有显式格式区段（含上述预览、可见字符
  数、内嵌控制符数），按逻辑位置排序
* `statistics`：按缩写/级别/类型的计数、未闭合数、stray 数、溢余数、
  自动闭合数、各类区段数、段落数与字符数

### `GET /api/v1/audits`（按风险级别和文件名查询记录）

| 参数 | 说明 |
|---|---|
| `risk_level` | `none`/`low`/`medium`/`high`/`critical`，非法值返回 422 |
| `filename` | 文件名；默认精确匹配 |
| `fuzzy_filename` | `true` 时改为 `%filename%` 子串匹配 |
| `limit` / `offset` | 分页，limit 1–200，默认 50 |

返回摘要列表（不含完整 findings，体积小），按 id 倒序。

### `GET /api/v1/audits/{id}`

返回单条完整记录（含 `report`、原文与全部 findings/预览），不存在返回 404。

### `GET /api/v1/stats/risk`

按风险级别统计记录数：`{total, none, low, medium, high, critical}`。

### `GET /health`

存活探针：`{"status":"ok","version":"1.0.0"}`。

## Docker 启动

```bash
# 构建并后台启动（数据在命名卷 bidi-audit-data 中持久化）
docker compose up -d --build

# 查看健康状态 / 日志
curl http://localhost:8000/health
docker compose logs -f
```

仅用 Docker：

```bash
docker build -t bidi-audit-api .
docker run -d -p 8000:8000 \
  -v "$PWD/data:/data" \
  -e BIDI_DB_PATH=/data/audits.db \
  -e BIDI_MAX_DEPTH=60 \
  --name bidi-audit-api bidi-audit-api
```

容器启动时 `docker-entrypoint.sh` 会幂等执行 `python init_db.py`
创建 `/data/audits.db` 及表结构；也带有 Docker HEALTHCHECK。

## 本地开发（无 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements-dev.txt
export BIDI_DB_PATH=./data/audits.db   # 默认值是容器路径 /data/audits.db
python init_db.py
uvicorn app.main:app --reload --port 8000
pytest -q                              # 19 个测试
```

配置项（环境变量）：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `BIDI_DB_PATH` | `/data/audits.db` | SQLite 文件路径，目录不存在会自动创建 |
| `BIDI_MAX_DEPTH` | `60` | 显式格式/隔离嵌套深度上限 |

## 使用示例

```bash
# RLO 反转攻击：屏幕上看似 cod.js，逻辑文件名其实以 .exe 结尾
curl -s http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text":"report\u202ecod.js\u202c.exe","filename":"payload.exe"}' | jq

# 只看高危记录
curl -s 'http://localhost:8000/api/v1/audits?risk_level=high' | jq

# 按文件名子串查询
curl -s 'http://localhost:8000/api/v1/audits?filename=payload&fuzzy_filename=true' | jq

# 取完整报告（含转义预览）
curl -s http://localhost:8000/api/v1/audits/1 | jq '.report.dangerous_spans'
```

典型 RLO 样例的输出片段：

```json
{
  "abbreviation": "RLO",
  "code_point": "U+202E",
  "logical_index": 6,
  "severity": "high",
  "matched": true,
  "unclosed": false,
  "influence_span": {
    "start": 6,
    "end": 14,
    "escaped_preview": "\u202ecod.js\u202c",
    "named_preview": "<RLO>cod.js<PDF>"
  }
}
```

## 设计说明与边界

* 本服务做的是**控制符结构审计**，不是完整 UBA 重排序引擎；所有结论
  （配对、范围、未闭合）对任何符合 UAX #9 的渲染器都成立。
* `approx_visual_preview` 仅反转覆盖区内的可显示字符，用于演示，不
  处理数字、中性符、连写与镜像字形，不能替代真实渲染快照。
* 逻辑索引按 Unicode 码点计数（非 UTF-16 码元、非字节偏移）。
* SQLite 写入为同步本地事务，适合单实例审计/评审场景；如需高并发可
  替换 `app/db.py` 或加 WAL。
