# argus-templates

[English](README.md)

给 [argus](https://github.com/guaidao2/argus) 用的插件集合。它们不放在扫描器本体里，
这样就能按自己的节奏发布、修正和定版。

插件就是**一份 YAML 文档**：argus 只解析它，不执行其中任何东西。正因如此，这样的集合
才成立——模板是数据，不需要为了它去构建扫描器。完整 schema 见 argus 的
[插件指南](https://github.com/guaidao2/argus/blob/main/docs/plugin-guide.zh-CN.md)；
本仓库的每个模板各自说明它把 schema 用在了哪里。

## 模板列表

| 模板 | 目标 | 贡献 |
| --- | --- | --- |
| [`rpcbind/`](rpcbind/) | ONC RPC portmapper，TCP/UDP 111 | 用 RPCB v3 的应答识别该端口（让交出的文本进入报告），并把它的注册表渲染出来：每个已注册程序一条带名字的 finding，外加 UDP 反射放大这一面 |

## 安装

```bash
argus --register-plugin ./rpcbind/rpcbind.yaml   # 单个文档
argus --register-plugin ./rpcbind/               # 目录 = 一个插件包（先读它的 README）
argus --plugin-dir ./rpcbind/rpcbind.yaml -sV --findings -p 111 10.0.0.9   # 仅本次运行，不写注册表
```

注册目录会**递归**加载其中每个 `*.yaml`，所以注册目录之前请先看该模板的 README：模板可能
在默认文档旁边再放一份可选的第二文档。

模板用 `argus_min_version` 声明它需要的 argus 版本，因此更旧的构建会直接拒绝加载，而不是
悄悄只做一半的活。

## 验证模板

对线缆字节下结论的模板，都应当自己证明这些结论。每个模板都带一套脚本：用真实 argus
二进制去打目标服务的 mock，再核对报告——**包括那些必须不命中的情况**：

```bash
cd argus && go build -o /tmp/argus ./cmd/argus
cd ../argus-templates
python rpcbind/test/verify.py --argus /tmp/argus
```

## 贡献模板

约定来自 argus 内置规则文件的写法：

1. **探测字节要精确。** 在注释里逐字段写出线缆格式，并用 mock 证明这些字节，而不是靠推理。
   `send:` 里的字节用 YAML 双引号转义（`"\x80\x00..."`）：YAML 解成码点，argus 再把
   `U+0100` 以下的每个 rune 还原成一个字节。`pattern:` 用**单引号**，让反斜杠原样交给 RE2；
   并记住响应按 latin-1 解码后匹配，这才使 `\xNN` 表示**字节** NN。
2. **pattern 只能命中它声称的东西。** 要求成功应答的形状；优先使用只出现在成功应答里的内容
   而不是状态码；列表元素要锚定到它的编码。如果一条规则能被"其实意味着别的"的应答满足，
   它就还没写完。
3. **严重的级别要诚实。** finding 是模式匹配，不是证明。在描述里写清观测到什么、意味着什么、
   不确定在哪；级别衡量影响："这是暴露面，不是缺陷"该写就得写。
4. **不做会改变目标状态的事。** 会改状态的、会触发拒绝服务的、需要跟第三方主机说话的探测，
   一律不写，无论结论多诱人。把排除理由和手工检查方法写下来代替。
5. **finding 双语。** `title` 与 `description` 是含 `en`、`zh` 的语言映射；参考链接与工具名
   不翻译。
6. **README 要说清信息落在报告的哪里**、模板刻意不做什么、以及它是怎么被验证的。
7. **测试要带反例。** 一个"必须保持沉默"的场景，比多一个正例更有价值。

RE2 上花过时间的坑：`\x0[2-4]` 是非法转义而不是 pattern（写 `[\x02-\x04]`）；不支持前瞻；
插件无法把提取出的值插入 finding 文本，所以把要展示的信息写进 finding 标题。

## 许可

MIT。见 [LICENSE](LICENSE)。
