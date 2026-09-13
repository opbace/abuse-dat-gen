# abuse-dat-gen

[English](README.md)

每日自动构建的 **V2Ray / Xray geosite 文件**，收录恶意软件、钓鱼等滥用域名。数据来自
[HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists)（GPL-3.0），提供三个档位。

适用于代理/VPN 服务器：防止客户端（包括中了恶意软件的设备）经由服务器访问 C&C 与钓鱼基础设施。

> ⚠️ 部署前请阅读[免责声明](DISCLAIMER.md)。黑名单一定会有误杀，本项目只做上游数据的格式转换。

## 文件

每个文件只含一个分类 `abuse`，换档位只需改路由规则里的文件名。

| 文件 | 来源 | 规则数 | 大小 | Xray 规则 |
|---|---|---:|---:|---|
| `abuse.dat` | HaGeZi TIF（完整） | 约 243 万 | 约 53 MiB | `ext:abuse.dat:abuse` |
| `abuse-medium.dat` | HaGeZi TIF（medium） | 约 68.6 万 | 约 15 MiB | `ext:abuse-medium.dat:abuse` |
| `abuse-mini.dat` | HaGeZi TIF（mini） | 约 17.7 万 | 约 4 MiB | `ext:abuse-mini.dat:abuse` |

小档位是大档位的严格子集。HaGeZi 对 medium 的说明是"只保留最重要的数据源"，mini 是在 medium 基础上再压缩体积的版本。

### 内存

2026-09-13 实测（macOS arm64）。加载后占用的内存远大于文件本身，**选档位前请先对照服务器内存**：

| 文件 | Xray 进程 RSS（加载峰值） | Xray 进程 RSS（约 2.5 分钟后） | GC 后常驻 Go 堆 |
|---|---:|---:|---:|
| `abuse.dat` | ~1,655 MiB | ~1,560 MiB | 约 217 MiB |
| `abuse-medium.dat` | ~472 MiB | ~472 MiB | 约 58 MiB |
| `abuse-mini.dat` | ~147 MiB | ~61 MiB | 约 15 MiB |
| 不加载 geosite 文件 | ~30 MiB | ~30 MiB | — |

进程 RSS 用 Xray 26.7.28 实测，规则为 `ext:<文件>:abuse` 转发到 blackhole。Go 堆一列用 Xray v26.3.27 的配置加载器和域名匹配器测得，
每次发布流程都会重新测量并写进 job summary。Go 把空闲内存归还给系统的时机不固定：之前一次测试里完整版 2 分钟后 RSS 降到约 853 MiB，
这次一直接近峰值。Linux 上的绝对数值会有差异，**请按峰值规划内存**。

## 下载

项目地址：<https://github.com/opbace/abuse-dat-gen>

最新构建发布在 `release` 分支：

| 文件 | 地址 |
|---|---|
| `abuse.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse.dat> |
| `abuse-medium.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse-medium.dat> |
| `abuse-mini.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse-mini.dat> |
| `sha256sums.txt` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt> |
| `manifest.json` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/manifest.json> |

分支上还有 `LICENSE`、`NOTICE.md`、`DISCLAIMER.md`。该分支只有一个提交，每次构建整体替换，不保留历史版本。

下载并校验（以 medium 为例）：

```sh
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse-medium.dat
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt
sha256sum --check --ignore-missing sha256sums.txt
```

`manifest.json` 记录输入源的 URL / 时间 / SHA-256 / 许可证、每个文件的规则条数，以及每一条被过滤掉的规则。

[GitHub Releases](https://github.com/opbace/abuse-dat-gen/releases) 保留最近 14 次构建作为存档，
其中额外附带文本规则 `abuse.txt`、`abuse-medium.txt`、`abuse-mini.txt`（每行一条规则）。

大量服务器请从自己的镜像拉取，不要直接打 GitHub。

## 在 Xray 中使用

把文件放进 Xray 的资源目录（与 `geosite.dat` 同目录，或 `XRAY_LOCATION_ASSET` 指定的目录）：

```json
{
  "type": "field",
  "domain": ["ext:abuse-medium.dat:abuse"],
  "outboundTag": "block"
}
```

域名规则只有在 Xray 知道目标域名时才生效。客户端直连 IP 的情况，需要在 inbound 上开启 `sniffing`，
并把 `destOverride` 设为 `http`、`tls`、`quic`。

## 构建流程要点

- HaGeZi 的 `*.example.com` 转为 `domain:`（含子域）。
- **公共后缀过滤**：PSL 显式列出的共享命名空间（`github.io`、`co.uk`、`camdvr.org` 这类 DDNS）上的
  `domain:` 规则会误伤该命名空间下所有无关用户，因此删除；其下的单个站点仍保留。
  仅因 PSL 通配规则才算后缀的名字（如 `*.localto.net` 下的某个隧道）是单一租户，保留。
- **白名单**：会拦到 [`allowlist.txt`](allowlist.txt) 中域名（及其子域）的规则会被删除。
- **发布闸门**（任一文件触发即失败）：条数低于下限、无效行超过 1%、比上一版缩水超过 25%、白名单仍被命中、
  dat 解码不一致、Xray 无法加载或拦截了 `google.com` 等知名域名——上一版保持发布状态。

## 误杀反馈

请向 [HaGeZi](https://github.com/hagezi/dns-blocklists/issues) 报告，下次构建自动生效。

## 维护者须知

- 公开仓库 60 天无活动时，GitHub 会停用定时工作流；留意通知邮件，否则每日构建会停止。
- 发布流程会强制推送 `release` 分支，并自动删除最近 14 个之外的 GitHub release（`KEEP_RELEASES`）。
  `abuse.dat` 超过 GitHub 建议的 50 MB，推送时会打印警告，硬上限是 100 MB。

## 许可证

GPL-3.0-only。第三方署名见 [`NOTICE.md`](NOTICE.md)。
