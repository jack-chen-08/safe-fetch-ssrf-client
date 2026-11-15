# safe_fetch —— 带 SSRF 防护的情报抓取 HTTP 客户端

情报模块（`intel/`）唯一的出站 HTTP 出口。抓外部简报源时，所有 URL 都必须过这个函数，
情报模块内部不得直接使用 `requests` / `httpx` / `urllib.request`。

- Python 3.11+，**零第三方依赖**（只用 `socket` / `ssl` / `http.client` / `ipaddress` / `zlib`）
- 默认参数即安全参数：`safe_fetch(url, source)` 不传 config 就是全防护
- 拦截必留痕：每次拒绝写一条结构化安全日志（URL / 解析 IP / 原因）

```python
from intel.safe_fetch import safe_fetch, Source, ErrorCode, FetchBlocked

FEED = Source(name="example-rss", allowed_hosts=("example.com", "feeds.example.com"))

try:
    result = safe_fetch("https://feeds.example.com/rss", FEED)
    print(result.status_code, result.content_type, len(result.body))
except FetchBlocked as exc:
    print(exc.code, exc.reason, exc.resolved_ips)
```

---

## 1. 威胁模型

情报抓取端的 URL 有两个来源：**配置里写死的源地址**和**第三方内容里的链接**。后者不可信。
我们把不可信 URL 可能造成的伤害归纳为四类，本模块逐一封堵：

| # | 威胁 | 攻击者怎么用 | 本模块的对策 |
|---|------|-------------|-------------|
| T1 | 内网横向探测 | 把 URL 指向 `10.0.0.5`、`192.168.x.x`，用响应时间/状态码判断内网资产存活 | 解析后校验全部 IP，命中私网段直接拒（规则 3） |
| T2 | 云元数据窃取 | 指向 `169.254.169.254`，读走实例角色的临时凭证 | 同上，且元数据地址单列，日志原因写明「云元数据」 |
| T3 | DNS 重绑定（TOCTOU） | 第一次解析返回公网 IP 通过校验，建连前改成内网 IP | 自己解析一次拿定 IP，**建连直接用该 IP**，Host 头与 SNI 仍用域名（规则 4） |
| T4 | 重定向绕过 | 白名单域名 `302` 到内网或白名单外主机，把校验甩在身后 | 关闭自动重定向，手动跟随时**每一跳重跑完整校验**（规则 5） |

附加的两类资源型攻击：**压缩炸弹**（gzip 解压后膨胀到 GB 级撑爆内存）与**超大响应**
（拖住 worker 直到超时）。本模块对流式读取的**原始字节**和**解压后字节**分别计数，
任一路超 10MB 立即中断连接，而不是读完再判（规则 6）。

范围内不做的事：不做内容真实性判断、不解析 HTML、不做反爬对抗、不缓存。本模块只回答
「这个 URL 能不能安全地取，取到的字节有多大、是什么类型」。

---

## 2. 规则表

| # | 规则 | 代码位置 | 实现方式 |
|---|------|---------|---------|
| 1 | 仅 `http`/`https`，端口仅 80/443 | `policy.validate_target` | `urlsplit` 后校验 scheme 与 port（含默认端口补全）；显式拒绝带用户信息（`user:pass@`）的 URL，避免 Host 解析歧义 |
| 2 | 主机必须在 `source.allowed_hosts` 内，精确或子域名匹配，IDNA 规范化，去尾点 | `policy.normalize_host` / `policy.host_allowed` | 域名先 `idna` 编码为 punycode、转小写、去掉结尾点；匹配时要求 `host == allowed` 或 `host.endswith("." + allowed)`，`evil-example.com` 不会命中 `example.com` |
| 3 | 自行解析 DNS，所有解析结果不得落在禁止网段 | `policy.resolve_and_check` / `policy.classify_ip` | `getaddrinfo(AF_UNSPEC)` 拿全部 A/AAAA；**任一**结果命中禁止段则整体拒绝（fail-closed）；IPv4-mapped IPv6（`::ffff:10.0.0.5`）拆成 IPv4 再判 |
| 4 | 建连直接用已校验 IP，Host 头与 SNI 用域名 | `client.socket_transport` / `client._build_request` | `socket.create_connection((ip, port))` 直连 IP；HTTPS 用 `wrap_socket(server_hostname=host)` 保证证书按域名校验、SNI 正确；Host 头写域名不写 IP |
| 5 | 关闭自动重定向，手动跟随最多 3 跳，每跳重校验 1-4 | `client.safe_fetch` 主循环 | 不依赖任何自动跟随逻辑；读到 301/302/303/307/308 且带 `Location` 时 `urljoin` 出新 URL，回到循环头部重新执行规则 1-3；超过 3 跳抛 `TOO_MANY_REDIRECTS` |
| 6 | 连接 5s / 读取 15s / 总 30s；响应体与解压后均 ≤ 10MB | `client.safe_fetch` + `client._read_limited` | 连接与读超时分别设 `socket` timeout；每跳前用单调时钟算剩余预算；流式累计原始字节与解压字节，超限立即 `close()` 并抛 `TOO_LARGE` |
| 7 | Content-Type 仅 HTML / XHTML / RSS / Atom / XML / PDF | `client._check_content_type` | 取 `Content-Type` 的分号前主类型小写比对白名单；缺失或不在白名单一律 `BAD_CONTENT_TYPE`，在**读 body 之前**判定 |
| 8 | 不带 Cookie 与认证头，忽略系统代理环境变量 | `client._build_request`（不设这些头）+ 用 `http.client` 而非 `requests` | 请求头只有 `Host` / `User-Agent` / `Accept` / `Accept-Encoding` / `Connection`；`http.client` 本身不读 `HTTP_PROXY` 等环境变量，因此无隐式出口代理；本模块**不提供**代理参数（见 §6） |

### 禁止网段（规则 3 展开）

IPv4：`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、
`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.88.99.0/24`、`192.168.0.0/16`、
`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`、
`255.255.255.255/32`

IPv6：`::/128`、`::1/128`、`64:ff9b::/96`（NAT64）、`100::/64`、`2001:db8::/32`、`2002::/16`、
`fc00::/7`、`fe80::/10`、`ff00::/8`

单列：`169.254.169.254`、`fd00:ec2::254`（云元数据，日志原因单独标注）
表外兜底：`ipaddress` 的 `is_private` / `is_reserved` / `is_loopback` / `is_link_local` /
`is_multicast` / `is_unspecified` 任一为真同样拒绝（防新型保留段漏网）。

### 错误码

| code | 含义 | 触发点 |
|------|------|--------|
| `SSRF_BLOCKED` | 目标解析到禁止网段 | 规则 3 |
| `HOST_NOT_ALLOWED` | 主机不在白名单 / scheme 或端口非法 / URL 带用户信息 | 规则 1、2 |
| `TOO_MANY_REDIRECTS` | 超过 3 跳 | 规则 5 |
| `TOO_LARGE` | 原始或解压后超过 10MB | 规则 6 |
| `TIMEOUT` | 连接/读取/总时长超限 | 规则 6 |
| `BAD_CONTENT_TYPE` | 类型缺失或不在白名单 | 规则 7 |
| `BAD_URL` | URL 为空、无法解析、含控制字符 | 入参校验（扩展） |
| `NETWORK_ERROR` | DNS 失败、TCP/TLS 失败、连接被重置 | 传输层（扩展） |

`BAD_URL` 与 `NETWORK_ERROR` 是扩展码：规则只规定了六个，但把「入参非法」和「网络抖动」
塞进 SSRF 语义会让告警口径失真，故单列。`FetchBlocked` 异常同时携带
`code` / `url` / `host` / `resolved_ips` / `reason`，便于调用方按需分级。

---

## 3. 安全日志

每次拒绝都会写一条 `WARNING` 到 logger `intel.safe_fetch.security`，字段随 `LogRecord` 附加：

```
safe_fetch.blocked code=SSRF_BLOCKED source=example-rss
  url=https://example.com/brief host=example.com ips=10.0.0.5
  reason=解析结果 10.0.0.5 命中禁止网段（私网 A）
```

字段：`code`、`source`、`url`、`host`、`resolved_ips`、`reason`（`reason` 同时写进消息体，
让不解析 extra 的日志系统也能 grep 到）。库自带 `NullHandler`，接入时按需挂 handler：

```python
import logging
logging.getLogger("intel.safe_fetch.security").addHandler(logging.StreamHandler())
logging.getLogger("intel.safe_fetch.security").setLevel(logging.WARNING)
```

---

## 4. 验收标准对照

| # | 验收要求 | 对应测试 | 结果 |
|---|---------|---------|------|
| 1 | 解析到 `10.0.0.5` 或 `169.254.169.254` 的主机返回 `SSRF_BLOCKED`（本地桩 DNS） | `tests/test_policy.py::TestSsrfBlocking`（`stub_resolver` 桩掉 DNS，不触网） | 通过 |
| 2 | 重定向到白名单外主机或内网地址被拦截 | `tests/test_client.py::TestRedirects`（含「第二跳未发出请求」的断言） | 通过 |
| 3 | 解压后 >10MB 的 gzip 响应被中断返回 `TOO_LARGE` | `tests/test_client.py::TestSizeLimits::test_gzip_bomb_rejected`（11MB 零字节压成 <1MB，断言拦在解压后） | 通过 |
| 4 | 静态检查脚本确认情报模块内无绕过 `safe_fetch` 的出站请求 | `scripts/check_no_bypass.py` + `tests/test_static_guard.py`（对本仓库 PASS、对反面样例 FAIL，双向自证） | 通过 |

实测输出：

```
$ python3 -m unittest discover -s tests -t .
Ran 52 tests in 0.415s
OK

$ python3 scripts/check_no_bypass.py
[PASS] intel/ 内未发现绕过 safe_fetch 的出站请求（已跳过 safe_fetch/ 实现区）

$ python3 scripts/check_no_bypass.py tests/fixtures
[FAIL] fixtures/ 内发现 4 处绕过 safe_fetch 的出站请求：
  bypass_sample.py:7  FORBIDDEN_IMPORT  import urllib.request（urllib.request）
  bypass_sample.py:9  FORBIDDEN_IMPORT  import requests（requests）
  bypass_sample.py:13 FORBIDDEN_CALL    requests.get(...)
  bypass_sample.py:17 FORBIDDEN_CALL    request.urlopen(...)
```

全部 52 个用例**离线运行**：DNS 用桩函数，HTTP 用注入的桩传输层，不依赖网络、不需要
任何外部服务，可直接进 CI。真实 socket 路径由 `socket_transport` 承担，通过
`SafeFetchConfig(transport=None)` 使用（默认值）。

### 真实网络冒烟（`scripts/live_smoke.py`，不进 CI）

单测覆盖的是策略与闸门，真实建连路径另用冒烟脚本验证。实测输出：

```
$ python3 scripts/live_smoke.py
1) 正向：真实 HTTPS 抓取（IP 直连 + SNI）
  [OK ] https://example.com/  -> 200 text/html 577B ips=(172.66.147.243, 104.20.23.154, ...) (0.91s)
2) 正向：真实 HTTP 抓取
  [OK ] http://example.com/   -> 200 text/html 577B ips=(104.20.23.154, 172.66.147.243, ...) (1.48s)
3) 拦截：主机不在白名单      -> HOST_NOT_ALLOWED
4) 拦截：端口非法 8443       -> HOST_NOT_ALLOWED
5) 拦截：169.254.169.254     -> SSRF_BLOCKED「云元数据端点」
6) 拦截：10.0.0.5            -> SSRF_BLOCKED「私网 A (10.0.0.0/8)」
6/6 项符合预期
```

冒烟过程中发现并修掉一个真实缺陷：连接循环原实现在**第一个 IP 超时即抛 TIMEOUT**，
没有尝试同域名下的其它 A/AAAA 记录，导致某些边缘节点不可达时整次抓取失败。
现改为整个连接阶段共享 `connect_timeout` 预算、预算内逐个 IP 容错，实测 `http://example.com/`
的耗时从超时失败降到 1.48s。

---

## 5. 目录结构

```
intel/
  safe_fetch/
    errors.py     ErrorCode、FetchBlocked
    policy.py     规则 1-3：URL / 主机 / IP 校验
    client.py     规则 4-8：建连、重定向、体积、类型、日志
  briefing/
    sample_collector.py   演示：采集器只经 safe_fetch 出网
tests/
  test_policy.py        规则 1-3（含桩 DNS）
  test_client.py        规则 4-8（含炸弹、重定向、日志、请求头）
  test_static_guard.py  验收 4（双向自证）
  fixtures/bypass_sample.py  反面样例，仅供自证
scripts/
  check_no_bypass.py    静态检查（AST 级，可 --json 接 CI）
```

## 6. 已知边界与取舍

- **不提供出口代理参数**。经代理建连意味着由代理解析域名，规则 4 的 IP 固定随之失效。
  若确需出口代理，应在受控网关层实现，而不是放宽本模块。`http.client` 不读代理环境变量，
  所以默认行为就是「忽略系统代理」。
- **只实现 GET**。情报抓取是读操作；需要 POST 的场景请另立函数并重新过一遍规则 1-3。
- **不支持 HTTP/2、不支持 chunked 之外的传输编码**（`chunked` 由 `http.client` 处理）。
- **证书校验依赖系统信任库**，不做证书固定（pin）。需要 pin 时在 config 里注入自定义 `ssl.SSLContext`。
- **DNS 与建连之间仍有一个极短窗口**：我们只解析一次并直接连 IP，因此重绑定无法生效；
  但若攻击者控制 DNS 且能影响 `getaddrinfo` 的返回顺序，影响的只是「连哪个合法 IP」，不构成越权。
- 未做响应内容的病毒/内容安全扫描，这属于下游职责。
