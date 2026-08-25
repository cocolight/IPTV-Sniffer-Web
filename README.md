# IPTV Sniffer Web

当前稳定版本：`v1.2.9`

面向飞牛 NAS、Linux Docker 和交换机镜像口场景的 IPTV 频道发现与播放列表工作台。它用于捕获机顶盒开机流量、整理频道线路，并生成供播放器或 `rtp2httpd` 使用的 M3U 文件。

> 仅在你有权使用的网络和 IPTV 服务中部署。镜像口用于被动捕获，不能替代具备 IPTV 上游访问能力的播放设备。

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 频道发现 | 从机顶盒开机流量中解析频道表、组播地址、FCC/FEC 与 DHCP / IPTV 认证摘要。 |
| 频道整理 | 自动归组同名频道，保留主源和备选线路；可编辑名称、分类、EPG 标识与高清标记。 |
| 导入与备份 | 导出或按模块恢复全局备份；也可重新导入本应用导出的 M3U、`rtp2httpd` 源文件和 `channels.json`。 |
| 播放列表 | 导出播放器最佳/全部线路、`rtp2httpd` 最佳/全部线路，以及飞牛影视 HLS 列表。 |
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
  roninriddle/iptv-sniffer-web:1.2.9
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
3. 在「频道线路」检查分组、主源和备选线路；必要时编辑频道元数据，并刷新/重新匹配 EPG 与台标。
4. 按用途导出：播放器使用 `channels-best.m3u` 或 `channels-all.m3u`；`rtp2httpd` 使用 `channels-rtp2httpd-best.m3u` 或 `channels-rtp2httpd-all.m3u`；飞牛影视使用 `channels-fnos-hls.m3u`。
5. 需要主动播放时，在「IPTV 认证」先查看捕获到的认证摘要；确认网络隔离与回退方案后，才使用实验性一键认证。
6. 播放异常时，在「播放诊断」填写 `rtp2httpd` 地址和频道地址，依次检查上游认证、IGMP、FCC 和组播回流。

## 导入、备份与恢复

「导入频道 / 恢复备份」是统一入口：

- 全局备份可按频道线路、运营商频道表、认证快照和设置等模块选择恢复，并兼容旧版备份与单接口认证备份；
- 可导入本应用先前导出的播放器 M3U、`rtp2httpd` 源 M3U，以及 `channels.json`，用于恢复频道线路；
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

如果频道带 FCC/FEC 参数，应用会在对应线路中保留这些信息。导出前的多线路健康检查会优先选择可读取媒体数据的源；单源频道不会额外探测。

## 回看与 HLS

直播与回看是两条独立链路：直播走组播、`rtp2httpd` 或本机 HLS 转封装；回看依赖运营商频道表中的时移地址和有效认证信息。回看 Token 通常绑定账号、机顶盒信息与 IPTV 地址，直播可用不代表回看可用。

- 开启回看后，播放器访问稳定的本机 `/hls/<key>/catchup` 地址；应用在后台更新实际回看地址。
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
| `POST` | `/api/diagnose` | 执行播放链路诊断。 |
| `POST` | `/api/catchup/refresh` | 刷新回看地址。 |

## 镜像与标签

- 测试版使用 `x.y.z-test`：发布同名 Git tag 和 Docker tag，不更新 `latest`。
- 正式版使用 `x.y.z`：发布同名 Git tag、Docker tag 和 `latest`。

## 版本演进

近期版本保留逐项记录；更早的连续小版本按主题合并，完整提交历史见 [GitHub Releases](https://github.com/roninriddle/IPTV-Sniffer-Web/releases) 和 [提交记录](https://github.com/roninriddle/IPTV-Sniffer-Web/commits/main)。

| 版本 | 更新摘要 |
| --- | --- |
| `v1.2.9` | 统一导入入口支持本应用导出的播放器/rtp2httpd M3U 与 `channels.json`，用于恢复频道线路；全局备份的模块化恢复继续保留。 |
| `v1.2.8` | 全局备份覆盖频道线路、运营商频道表、认证快照、设置与快照；支持按模块恢复、旧备份兼容及同名接口冲突保护；首页调整为步骤向导。 |
| `v1.2.7` | 新增频道元数据编辑与恢复自动识别值；手动修改可跨重新导入和 EPG 重新匹配保留。 |
| `v1.2.6` | 修复单字符频道名参与 EPG 模糊匹配时错误覆盖运营商频道名的问题。 |
| `v1.2.5` | 支持南京电信频道表解析，兼容多种门户下发格式、GBK/gzip/chunked 编码及频道分组。 |
| `v1.2.4–v1.2.1` | 完善 DHCP Option60 与 STB `channelAcquire` 解析；补齐北京联通频道、FCC/FEC、UserToken、抓包导出；改进回看认证 Profile、定时刷新、稳定回看入口和备份体验。 |
| `v1.2.0–v1.0.0` | 建立回看地址刷新、HLS 转封装、EPG/台标、接口认证备份恢复、线路评分、BPF 组播拦截诊断与多线路健康检查等核心能力。 |
| `v0.9.96–v0.6` | 收敛为交换机镜像口发现流程，加入 IPTV 认证助手、播放诊断与统一 Web 工作台。 |

## 参考与致谢

- [江苏电信 IPTV 回看源技术分析](https://www.right.com.cn/forum/thread-8314608-1-1.html)
- [`supzhang/get_iptv_channels`](https://github.com/supzhang/get_iptv_channels)
- [`zzzz0317/beijing-unicom-iptv-playlist`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist)
- [`zzzz0317/beijing-unicom-iptv-playlist-sniffer`](https://github.com/zzzz0317/beijing-unicom-iptv-playlist-sniffer)
- [`CGG888/SrcBox`](https://github.com/CGG888/SrcBox)
- [`epg.51zmt.top`](https://epg.51zmt.top:8001/)
- [`wanglindl/TVlogo`](https://github.com/wanglindl/TVlogo)
