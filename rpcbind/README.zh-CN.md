# rpcbind — 111 端口

[English](README.md)

把 111 端口主动交出来的信息，变成 argus 报告里的可读内容。111 是少数不用靠猜的
端口：问它要注册表，它会把该主机运行的每一个 RPC 程序点出来。本模板用 RPCB v3
的应答来识别该端口（v3 应答是 XDR 字符串，能直接在报告里读出内容），并把每一个
已注册程序渲染成报告里独立的一行。

```
$ argus -Pn -sV --findings -p 111 10.0.0.9

111/tcp open  rpcbind  ONC RPC portmapper (RPCB v3, registry readable)
| check: RPC: the portmapper disclosed its registry without credentials [LOW]
| One unauthenticated DUMP call returned every RPC program this host has registered...
| check: RPC registry: rexd (program 100017) is registered [MEDIUM]
| rexd is the remote execution service behind "on" and "rex"...
|_check: RPC registry: rusersd (program 100002) is registered [LOW]
```

## 它交出了什么，落在报告哪里

| rpcbind 交出的信息 | 出现在哪 | 怎么看 |
| --- | --- | --- |
| 注册表本身：注册了哪些程序、各自的版本与传输 | 每个程序一条 finding，`rule: rpcbind-registry` | `--findings` |
| netid、universal address、owner（RPCB v3 应答是 XDR 字符串，能按文本渲染） | 该端口的 banner（`service.banner`），`-v` 会打印，`-oX`/`-oJ` 始终保留 | `-sV` |
| "这是支持 RPCB 的 portmapper，不是上古 portmap" | 端口那一行：`rpcbind ONC RPC portmapper (RPCB v3, registry readable)` | `-sV` |
| 111/udp 同样在无凭据应答 | 一条 finding，`rule: rpcbind-udp-registry` | `--findings -sU` |
| 这些程序各自该接着做什么 | 端口上的 `--hack-reason` 笔记 | `--hack-reason` |

上表有两个必须说清的限制：

* 在本插件 schema 里，finding 的文本是**静态的**：它能写出程序号 `100017`，但无法把
  该程序实际监听的端口插进去。端口只能从 banner 读（universal address 最后两个数字
  是 256 进制的端口，所以 `0.0.0.0.8.1` 就是 2049），或者用 `rpcinfo -p` 取完整列表。
  argus 的 banner 上限是 200 字符，因此它承载的是注册表的**开头部分**，不是全部。
* 注册表是 portmapper 按设计就该应答的。"你能枚举这台主机"是暴露面陈述，不是缺陷，
  所以该 finding 定为 `low` 并在描述里写明这一点。

## 安装

需要 argus **1.0.1 或更新**；文档里声明了这一点，因此更旧的构建会直接拒绝加载，
而不是悄悄只做一半的活。

```bash
# 只装这一个文档（仅 111 端口）——推荐
argus --register-plugin ./rpcbind/rpcbind.yaml

# 或者装整个目录，会同时启用下面的 any-port 文档
argus --register-plugin ./rpcbind/
```

扫描：

```bash
argus -Pn -sV -p 111 10.0.0.9                        # 识别 + banner + 内置检测
argus -Pn -sV --findings -p 111 10.0.0.9             # 加上本模板的注册表渲染
argus -Pn -sV --findings -sU -p 111 10.0.0.9         # 加上 UDP 侧
argus -Pn -sV --findings --hack-reason -p 111 10.0.0.9
```

finding 必须加 `--findings` 才会出现，与内置检测一致：它们的探测是有明确意图的请求，
因此需要显式开启。

## 覆盖范围

| 规则 | match id | 类型 | 严重级别 | 命中条件 |
| --- | --- | --- | --- | --- |
| `rpcbind-rpcb-v3` | `rpcb-v3` | fingerprint | — | 端口应答 RPCB v3 DUMP：识别并显示交出的文本 |
| `rpcbind-rpcb-v3-udp` | `rpcb-v3-udp` | fingerprint（udp） | — | 同上，UDP 侧 |
| `rpcbind-registry` | `unauth-dump` | check | low | DUMP 成功且注册表非空 |
| `rpcbind-registry` | `rexd` | check | medium | 程序 100017 已注册（远程执行） |
| `rpcbind-registry` | `rusersd` | check | low | 程序 100002（当前登录用户） |
| `rpcbind-registry` | `rstatd` | check | low | 程序 100001（运行时长、负载、计数） |
| `rpcbind-registry` | `walld` | check | info | 程序 100008（向所有终端写消息） |
| `rpcbind-registry` | `sprayd` | check | low | 程序 100012（由客户端指定目标的流量生成器） |
| `rpcbind-registry` | `bootparam` | check | low | 程序 100026（网络引导参数） |
| `rpcbind-registry` | `keyserv` | check | low | 程序 100029（secure RPC 密钥） |
| `rpcbind-registry` | `amd-amq` | check | low | 程序 300019（automounter 控制接口） |
| `rpcbind-udp-registry` | `udp-amplification` | check（udp） | medium | UDP 上应答了 DUMP |
| `rpcbind-any-port`（独立文档） | `rpcb-v3` | fingerprint | — | **任意**开放端口上的 RPCB v3 应答 |

程序号取自 `/etc/rpc` / `rpc(5)`。NFS/NIS 家族（100003 nfs、100004 ypserv、
100005 mountd、100011 rquotad、100021 nlockmgr、100024 status、100227 nfs_acl）
在这里是**故意不重复**的：内置的 `checks-rpc` 已经在报它们，同一注册项出两条 finding
只会让每台跑 rpcbind 的主机都翻倍噪声。本模板补的是现代 `/etc/rpc` 仍然在列、而内置
集合没有提到的那些 SunOS 时代遗留守护进程。

严重级别只有一条标准：某个守护进程被注册是**事实**，级别表述的是这个**服务**对攻击者
值多少。`rexd` 以极薄的认证执行命令，所以是 `medium`；用户与主机枚举是 `low`；向所有
终端广播是 `info`；注册表本身是 `low`，因为应答 DUMP 正是 portmapper 的本职。这里没有
`high`/`critical`，也没有对未观测到的东西下漏洞结论——"已注册"就是被测量到的事实。

## 证据规则

每条 pattern 都写成"只可能在它声称的事实上命中"的形状。

* **只认成功应答。** 每条 pattern 都以应答头开头：`xid, REPLY, MSG_ACCEPTED,
  AUTH_NULL verifier, SUCCESS`，写作 `(\x00\x00\x00\x01){2}(\x00\x00\x00\x00){4}`。
  老式 portmap 对 v3 调用回的是 `PROG_MISMATCH`，那个位置不是 `SUCCESS`，因此 RPCB
  规则不可能把"不支持 RPCB 的 portmapper"认成支持者。`test/verify.py` 的自检直接拿
  `PROG_MISMATCH` 字节断言这一点。
* **v3 的 pattern 命中不了 v2 应答。** portmap v2 的应答从头到尾都是四字节字，根本不含
  netid 字符串；RPCB pattern 要求 `prog 100000, vers 2|3|4, <长度 3|4> "tcp"|"udp"`，
  这是只有 RPCB 应答才具备的形状。自检会把两种应答都喂进去。
* **注册项锚定在它的元素标记上。** XDR 把列表编码成"每个元素前一个 bool，最后以 0
  收尾"。所以程序号之前的四个字节前三位为 0，最后一位**允许是 0 也允许是 1**：列表
  最后一个元素前面就是 0。若强求 `\x00\x00\x00\x01`，恰好在该程序是列表最后一项的主机上
  会静默失效。`rexd-last` 场景覆盖了这种情况。
* **空注册表不构成泄露。** `unauth-dump` 要求列表非空（"还有后续条目"标记），因此没有
  注册任何程序的 portmapper 不会产出"泄露了注册表"的结论。自检里断言了这一点。
* **没回应的 v2 不该报。** UDP 没有 record marking，服务器无法解码的数据报根本不会被
  应答；所以 UDP 探测拿到应答，意味着真的是 portmapper 回复了 DUMP，而不是某个服务把
  字节原样吐了回来。
* **一个 probe 就是一次写、一次读。** 每个 probe 都完整带上它那次调用所需的 40 字节
  XDR，字段布局写在注释里；`test/verify.py` 的链路日志会在 probe 于 socket 中留下多余
  字节时直接判失败。

## 刻意不做的事

* **从不发送 `SET` 与 `UNSET`。** 它们会改动注册表，一次成功的 `UNSET` 会把正在使用的
  映射从运行中的主机上摘掉。那是攻击，不是检测。hack-reason 笔记里也写明了这点，以及
  它们为何同时被限制在回环传输上。
* **不探测 CVE-2017-8779（rpcbomb）。** 它是经 `RPCBPROC_CALLIT` 触发的内存耗尽，也就是说
  那一次探测**本身就是拒绝服务**。它同时还是版本问题：rpcbind 0.2.4 及以下、libtirpc
  1.0.1 及以下受影响，而 ONC RPC 服务器从不报告自己的版本。请在主机上读软件包版本。
  这一点写在 hack-reason 笔记里，让看报告的人一定能看到。
* **不用 `GETPORT`/`GETADDR` 做逐程序检测。** 那会和内置的 NFS/NIS 结论重复，并且为注册表
  已经携带的信息再发一次请求。
* **没有 any-port 检测。** any-port 文档只做识别，也不需要自己的检测：`rpcbind.yaml`
  里的规则同时绑定 `service: rpcbind` 与 111 端口，所以它们会跟随该服务到任何被识别出来的
  端口上，包括这份文档找到的那个。
* **不做间接调用探测。** 那是另一个工具的职责，而且那意味着要去跟被扫主机的**客户端**说话。

## 如何验证

```bash
python test/verify.py --argus /path/to/argus      # 或 --argus ./argus.exe
```

该脚本会启动 `test/fake-rpcbind.py`——一个严格的 mock portmapper（portmap v2 与 RPCB v3、
TCP record marking 与 UDP、无法解码的数据报静默丢弃、不支持的协议版本回 `PROG_MISMATCH`）
——再用真实 argus 对着它跑并核对报告：

| 场景 | 证明了什么 |
| --- | --- |
| `modern : tcp/111 : template` | 每个已注册程序都被报告；banner 带着交出的 netid、universal address 与 owner；`method` 是 `probed` 而不是端口表猜出来的 |
| `checks are opt-in` | 不加 `--findings` 时一条 finding 都没有 |
| `v2only` | 老 portmap 仍被识别（由内置规则），且 RPCB 规则不会冒领 |
| `rexd-last` | 位于注册表**最后一项**的程序依然会被报告 |
| `http` | 不是 RPC 的端口不会产出任何 RPC 结论 |
| `udp/111 : template` | 该端口在 UDP 上是 open，因此 UDP 侧同样被识别，放大结论也会触发 |
| `built-in rules only` | 基线：仅内置规则也能识别并报 NFS 家族，且链路上没有多余字节（字节数 44 = 声明 40 的 4 字节 marker + 40 字节调用） |
| `any-port document` | 非标准端口上的 rpcbind 会被识别，**并且**模板的检测会跟随该服务到那里 |
| pattern 自检 | v2 应答、空注册表、`PROG_MISMATCH` 都不该满足 v3/`unauth-dump` 的 pattern |

脚本需要能绑定 111（因为模板的 check 绑在该端口上）。在 Linux 上这意味着 root 或
`CAP_NET_BIND_SERVICE`；绑定失败时它会明确报错，而不是悄悄跳过。若拿 1.0.1 之前的构建运行，
它也会直接说明，而不是丢给你一屏失败。

## 编写要点

写给本仓库下一个模板：

* `send:` 里用 YAML 双引号转义写字节（`"\x80\x00..."`）：YAML 会解成码点，argus 再把
  `U+0100` 以下的每个 rune 还原成一个字节。`pattern:` 里要用**单引号**，让反斜杠原样交给
  RE2（`'\x80\x00...'`）；并记住响应是按 latin-1 解码后匹配的，这才使 `\xNN` 表示**字节** NN。
* RE2 的 `\x` 转义里不能放通配数字：`\x0[2-4]` 是非法转义而不是 pattern。要写成
  `[\x02-\x04]`。
* 把交出的程序号写进 finding 的**标题**，因为文本是静态的：
  "RPC registry: rexd (program 100017) is registered" 读起来就是清单里的一行，而且无论它
  监听在哪个端口都成立。

## 参考资料

* RFC 1833，rpcbind 协议（RPCB v2/v3/v4、过程号、universal address）：
  <https://www.rfc-editor.org/rfc/rfc1833.html>
* RFC 1057，portmap v2 协议：<https://www.rfc-editor.org/rfc/rfc1057.html>
* `rpc(5)`，上面用到的程序号表：<https://man7.org/linux/man-pages/man5/rpc.5.html>
* US-CERT TA14-017A，UDP 放大攻击（portmap 的带宽放大倍数 7 至 28）：
  <https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks>
  以及该公告的存档文本：<https://seclists.org/cert/2017/236>
* CVE-2017-8779（rpcbomb）：
  <https://security-tracker.debian.org/tracker/CVE-2017-8779>

## 许可

与本仓库一致，MIT。见 `../LICENSE`。
