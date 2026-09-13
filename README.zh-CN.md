# abuse-dat-gen

[English](README.md)

每日自动构建的 **V2Ray / Xray geosite 文件**，收录恶意软件、钓鱼等滥用域名，数据来自以下公开黑名单：

- [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists)（GPL-3.0）
- [CyberHost.uk Malware Blocklist](https://cyberhost.uk/malware-blocklist)（CC BY-SA 4.0）

适用于代理/VPN 服务器：防止客户端（包括中了恶意软件的设备）经由服务器访问 C&C 与钓鱼基础设施。

> ⚠️ 部署前请阅读[免责声明](DISCLAIMER.md)。黑名单一定会有误杀，本项目只做上游数据的格式转换。

## 下载

项目地址：<https://github.com/opbace/abuse-dat-gen>

最新构建发布在 `release` 分支：

| 文件 | 地址 |
|---|---|
| `abuse.dat` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse.dat> |
| `sha256sums.txt` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt> |
| `manifest.json` | <https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/manifest.json> |

分支上还有 `LICENSE`、`LICENSE-CC-BY-SA-4.0.txt`、`NOTICE.md`、`DISCLAIMER.md`。
该分支只有一个提交，每次构建整体替换，不保留历史版本。

下载并校验：

```sh
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/abuse.dat
curl -fLO https://raw.githubusercontent.com/opbace/abuse-dat-gen/release/sha256sums.txt
sha256sum --check --ignore-missing sha256sums.txt
```

`manifest.json` 记录输入源的 URL / 时间 / SHA-256 / 许可证、规则条数，以及每一条被过滤掉的规则。

[GitHub Releases](https://github.com/opbace/abuse-dat-gen/releases) 保留最近 14 次构建作为存档，
其中额外附带文本规则 `abuse.txt`（每行一条 `domain:` / `full:`）。

大量服务器请从自己的镜像拉取，不要直接打 GitHub。

## 分类

`abuse.dat` 只含一个分类 `abuse`：HaGeZi Threat Intelligence Feeds 与 CyberHost 恶意域名黑名单的并集，约 249 万条规则。

2026-09-13 用 Xray v26.3.27 自身的配置加载器和域名匹配器实测，GC 后常驻堆约 **219 MiB**，加载过程中峰值更高。
每次发布流程都会重新测量并写进 job summary。**部署前请核对服务器内存是否足够。**

## 在 Xray 中使用

把 `abuse.dat` 放进 Xray 的资源目录（与 `geosite.dat` 同目录，或 `XRAY_LOCATION_ASSET` 指定的目录）：

```json
{
  "type": "field",
  "domain": ["ext:abuse.dat:abuse"],
  "outboundTag": "block"
}
```

域名规则只有在 Xray 知道目标域名时才生效。客户端直连 IP 的情况，需要在 inbound 上开启 `sniffing`，
并把 `destOverride` 设为 `http`、`tls`、`quic`。

## 构建流程要点

- **HaGeZi** 的 `*.example.com` 转为 `domain:`（含子域）；**CyberHost** 官方说明是精确匹配，转为 `full:`。
- **公共后缀过滤**：PSL 显式列出的共享命名空间（`github.io`、`co.uk`、`camdvr.org` 这类 DDNS）上的
  `domain:` 规则会误伤该命名空间下所有无关用户，因此删除；其下的单个站点仍保留。
  仅因 PSL 通配规则才算后缀的名字（如 `*.localto.net` 下的某个隧道）是单一租户，保留。`full:` 规则一律保留。
- **白名单**：会拦到 [`allowlist.txt`](allowlist.txt) 中域名（及其子域）的规则会被删除。
- **发布闸门**：条数低于下限、无效行超过 1%、比上一版缩水超过 25%、白名单仍被命中、
  dat 解码不一致、Xray 无法加载或拦截了 `google.com` 等知名域名——任一成立则构建失败，上一版保持发布状态。

## 误杀反馈

请向收录该域名的上游报告，下次构建自动生效：
[HaGeZi](https://github.com/hagezi/dns-blocklists/issues) ·
[CyberHost](https://cyberhost.uk/malware-blocklist)

## 维护者须知

- 公开仓库 60 天无活动时，GitHub 会停用定时工作流；留意通知邮件，否则每日构建会停止。
- 发布流程会强制推送 `release` 分支，并自动删除最近 14 个之外的 GitHub release（`KEEP_RELEASES`）。
  `abuse.dat` 超过 GitHub 建议的 50 MB，推送时会打印警告，硬上限是 100 MB。

## 许可证

GPL-3.0-only。第三方署名，以及 CyberHost 的 CC BY-SA 4.0 数据为何可以按 GPL 分发，见 [`NOTICE.md`](NOTICE.md)。
