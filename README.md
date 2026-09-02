# IPTV Sniffer Web

当前稳定版本：`v1.3.2`

面向飞牛 NAS、Linux Docker 和交换机镜像口场景的 IPTV 频道发现、订阅管理与播放工作台。它捕获机顶盒开机流量，将频道加入订阅，并提供可长期固定使用的播放器订阅地址。

### 原始抓包归档与备份

每次完成机顶盒开机捕获后，原始 PCAP 会持久保存到数据卷的 `stb-captures/` 目录；容器重启、重新部署或网页重置都不会删除它。频道发现页可导出最近一份原始 PCAP，也可下载包含原始 PCAP、脱敏协议清单和说明的 ZIP 备份包，供日后离线重新解析。

PCAP 可能包含认证报文，因此不会纳入普通 JSON 配置备份，也不会通过状态接口或应用日志展示。请只保存在受信任的本地存储中。

> 仅在你有权使用的网络和 IPTV 服务中部署。镜像口用于被动捕获，不能替代具备 IPTV 上游访问能力的播放设备。

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 频道发现 | 从机顶盒开机流量中解析频道表、组播地址、FCC/FEC 与 DHCP / IPTV 认证摘要。 |
| 订阅中心 | 从频道库选择已订阅频道；主订阅、HLS 订阅和 EPG 地址固定不变，频道源、FCC 或回看地址刷新后自动生效。 |
| 频道库 | 按频道平铺浏览和筛选；可查看组播地址、EPG、HD / 4K、FCC、回看、时移与订阅状态，并批量管理订阅。 |
| 导入与备份 | 导出或按模块恢复全局备份；也可重新导入本应用导出的 M3U、`rtp2httpd` 源文件和 `channels.json`。 |
| 静态导出 | 按已订阅频道导出播放器最佳/全部来源、`rtp2httpd` 源文件，以及飞牛影视 HLS 列表。 |
| EPG 与台标 | 匹配 XMLTV EPG 和 TVlogo；支持缓存刷新与重新匹配。 |
| 链路诊断 | 检查 `rtp2httpd`、IGMP、组播回流、FCC、镜像口和常见配置问题。 |
| 实验性认证助手 | 展示并备份接口状态，辅助完成 IPTV DHCP 认证、恢复接口状态及排查 egress BPF 组播拦截。 |

## 快速开始

创建持久化目录并启动正式镜像：

```bash
mkdir -p data output
docker run -d \
  --name iptv-sniffer-web \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e TZ=Asia/Shanghai \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/output:/app/output \
  roninriddle/iptv-sniffer-web:1.3.2
```

访问 `http://宿主机IP:8787`。

本地构建与运行：

```bash
mkdir -p data output
docker compose up -d --build
```

本地测试：

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

`data/` 保存频道、认证摘要、设置及回看信息；不要在升级或重建容器时删除它。`output/` 保存导出的播放列表和备份文件。

## 推荐拓扑与权限

```text
光猫 IPTV 口 → 交换机
  ├─ 机顶盒端口（镜像源）
  └─ Docker 宿主机网口（镜像目标）
```

在管理型交换机中将机顶盒端口设为镜像源、Docker 宿主机网口设为镜像目标。容器必须使用 host 网络；在 FNOS 的「高级设置 → 功能」中开启：

- `NET_RAW`：抓包和原始网络访问；
- `NET_ADMIN`：仅在使用实验性认证助手或接口路由调整时需要。

镜像口可以捕获和解析 STB 流量，但通常不能主动向 IPTV 上游发送 IGMP/FCC 请求。若要通过 `rtp2httpd` 主动播放，仍需有设备完成 IPTV 认证并可访问 IPTV 上游。

## 使用流程

1. 配置镜像口并以 host 网络启动容器。
2. 在「运营商频道」选择镜像网口、填写机顶盒 IP，开始捕获后重启机顶盒，再导入发现的频道。
3. 打开「订阅中心」；首次升级会自动把原有最佳频道加入订阅。到「频道库」勾选频道后，可加入或移出订阅。
4. 播放器优先使用固定的 `http://宿主机IP:8787/playlist.m3u`。需要兼容 HLS 时使用 `/playlist-hls.m3u`，XMLTV 使用 `/epg.xml`。这些地址不包含组播、RTSP、FCC 或认证材料。
5. 仅在需要离线副本或供 `rtp2httpd` 读取时，到「订阅中心 → 高级设置 / 静态导出」生成文件；未临时勾选频道库条目时，静态文件默认按已订阅频道导出。
6. 需要主动播放时，在「IPTV 认证」先查看捕获到的认证摘要；确认网络隔离与回退方案后，才使用实验性一键认证。
7. 播放异常时，在「播放诊断」填写 `rtp2httpd` 地址和频道地址，依次检查上游认证、IGMP、FCC 和组播回流。

## 固定订阅地址

| 地址 | 用途 |
| --- | --- |
| `/playlist.m3u` | 推荐的动态主订阅，使用稳定的 `/live/<频道ID>` 与 `/catchup/<频道ID>`。 |
| `/playlist-all.m3u` | 与主订阅内容相同的兼容别名；保留给已保存该地址的播放器配置。 |
| `/playlist-hls.m3u` | 将直播入口改为本机 HLS 兼容地址。 |
| `/epg.xml` | 已配置的 XMLTV EPG 订阅源。 |

默认端口为 `8787`，例如播放器填写 `http://192.168.3.6:8787/playlist.m3u`。如果部署时显式设置了 `WEB_PORT=8788`，则相应改为 `http://192.168.3.6:8788/playlist.m3u`。频道组播地址发生变化时，应用以运营商频道表中的当前记录更新内部转发目标，播放器不需要重新导入订阅。

稳定直播入口会以 `307` 临时跳转到当前 `rtp2httpd` 来源，并禁止缓存该响应。APTV、TiviMate 与 OTT Navigator 建议各做一次实机验证；若某播放器错误缓存跳转地址，应改用其重新加载订阅或关闭该播放器的播放列表缓存选项。

## 导入、备份与恢复

「导入频道 / 恢复备份」是统一入口：

- 全局备份可按频道库、运营商频道表、认证快照和设置等模块选择恢复，并兼容旧版备份与单接口认证备份；
- 可导入本应用先前导出的播放器 M3U、`rtp2httpd` 源 M3U，以及 `channels.json`，用于恢复频道库；
- 恢复认证快照时，如果本机存在同名接口，默认不覆盖；请先确认接口和网络状态再手动处理。

导入仅接受 IPv4 组播来源。不要把来源不明的备份或播放列表直接用于实验性认证操作。

## `rtp2httpd` 配置示例

`rtp2httpd` 默认端口为 `5140`。将导出的源文件保存到 rtp2httpd 可访问的位置，再配置：

```ini
external-m3u = file:///vol1/@appshare/rtp2httpd/channels-rtp2httpd-best.m3u
external-m3u-update-interval = 0
```

常见播放地址形态：

```text
http://rtp2httpd-host:5140/rtp/239.x.x.x:port
```

如果频道带 FCC/FEC 参数，应用会在对应来源中保留这些信息。导出前的多来源健康检查会优先选择可读取媒体数据的源；单源频道不会额外探测。

## 回看与 HLS

直播与回看是两条独立链路：直播走组播、`rtp2httpd` 或本机 HLS 转封装；回看依赖运营商频道表中的时移地址和有效认证信息。回看 Token 通常绑定账号、机顶盒信息与 IPTV 地址，直播可用不代表回看可用。

- 开启回看后，动态订阅会给支持回看的频道写入稳定的本机 `/catchup/<频道ID>` 地址；应用在后台更新实际回看地址，播放器不必重新导入。
- 遇到 403、超时或零字节时，优先检查 IPTV 认证 IP、账号/机顶盒字段、门户 Token 与到 IPTV 网段的路由。
- HLS 转封装按需启动 FFmpeg，空闲后自动停止。

## 安全与操作边界

实验性认证助手会修改选定接口的 MAC、IPv4 或 IPTV 相关路由，并提供初始状态备份和恢复。使用前请：

- 断开机顶盒 IPTV 线，避免 MAC 冲突；
- 确保 Web 管理页面经另一张网卡访问；
- 导出接口备份，确认恢复路径；
- 只在明确的测试窗口内操作。

项目不会主动替换默认路由，但错误的接口或路由配置仍可能导致宿主机失联。

## API 入口

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `POST` | `/api/stb_discovery/start` | 开始 STB 开机捕获。 |
| `POST` | `/api/stb_discovery/import` | 导入发现到的运营商频道。 |
| `POST` | `/api/channels/import-export` | 导入已导出的 M3U 或 `channels.json`。 |
| `POST` | `/api/iptv-auth/backup-import` | 恢复接口认证备份。 |
| `POST` | `/api/export` | 导出频道文件。 |
| `GET` | `/api/subscription` | 读取订阅频道清单和固定订阅入口。 |
| `POST` | `/api/subscription/candidates` | 加入、移出或重置已订阅频道。 |
| `POST` | `/api/diagnose` | 执行播放链路诊断。 |
| `POST` | `/api/catchup/refresh` | 刷新回看地址。 |

## 镜像与标签

- 测试版使用 `x.y.z-test`：发布同名 Git tag 和 Docker tag，不更新 `latest`。
- 正式版使用 `x.y.z`：发布同名 Git tag、Docker tag 和 `latest`。

## 版本演进

近期版本保留逐项记录；更早的连续小版本按主题合并，完整提交历史见 [GitHub Releases](https://github.com/roninriddle/IPTV-Sniffer-Web/releases) 和 [提交记录](https://github.com/roninriddle/IPTV-Sniffer-Web/commits/main)。

| 版本 | 更新摘要 |
| --- | --- |
| `v1.3.2` | 重构频道库为单一平铺视图：分类、订阅状态与 FCC / 回看 / 时移 / 4K 快捷筛选；直接显示 HD / 4K、能力与订阅状态；移除分组页面并收敛批量操作。 |
| `v1.3.1` | 修正订阅别名语义：`/playlist-all.m3u` 明确为主订阅兼容别名；订阅清单纳入全局备份、恢复与清除；回看入口统一为稳定 `/catchup/<频道ID>`；时移长度统一使用分钟字段并兼容旧数据。 |
| `v1.3.0–v1.2.0` | 建立从机顶盒抓包、频道发现、认证辅助、频道导入与备份恢复，到稳定动态订阅、直播 / FCC / 回看 / 时移、HLS、EPG、播放诊断的一体化工作流；覆盖联通、北京联通与电信频道表适配，支持原始 PCAP 归档和回归测试。 |
| `v0.9.96–v0.6` | 收敛为交换机镜像口发现流程，加入 IPTV 认证助手、播放诊断与统一 Web 工作台。 |

## 参考与致谢

- [江苏电信 IPTV 回看源技术分析](https://www.right.com.cn/forum/thread-8314608-1-1.html)
- [`supzhang/get_iptv_channels`](https://github.com/supzhang/get_iptv_channels)
- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)
- [江苏电信 IPTV 认证与频道获取实践](https://www.right.com.cn/forum/thread-8314231-1-1.html)
- [自动抓取 IPTV 单播地址，实现时移回看（一）](https://www.bandwh.com/net/2571.html)：镜像抓包、DHCP Option60 / STB 标识、IPTV 网口与策略路由。
- [自动抓取 IPTV 单播地址，实现时移回看（二）](https://www.bandwh.com/net/2637.html)：`rtp2httpd`、FCC、M3U 回看时间参数与客户端兼容性。
- [`suzukua/iptv-cd-telecom`](https://github.com/suzukua/iptv-cd-telecom)：直播、FCC、回看和 APTV 等播放器的 M3U 集成参考。
- [IPTV 单播 RTSP 路由与回看实践（NGA）](https://ngabbs.com/read.php?tid=41933257&rand=555)：单播回看可达性与 IPTV 专网路由排障参考。
- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)
