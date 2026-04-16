# smtp-analyzer

SMTP 流量完整性分析工具，用于解析 pcap/pcapng 抓包文件中的 SMTP 流量，判断每条连接是否完整、是否双向，并输出异常标签。

## 功能

- 解析 pcap / pcapng 格式抓包文件
- 支持 VLAN（包括 QinQ 双层 VLAN）
- 自动识别 SMTP 握手、EHLO/HELO、DATA、STARTTLS、隐式 TLS 等阶段
- 判断每条 TCP 流的完整性（TCP 握手 + 载荷 + 关闭）
- 判断双向性（客户端与服务端是否均有数据）
- 对比严格 VLAN 视图与忽略 VLAN 视图，自动诊断 VLAN 不对称导致的拆流现象
- 输出异常标签（`tcp_no_handshake`、`smtp_missing_banner` 等）
- 支持 JSON 和 CSV 格式报告输出

## 安装

### 依赖

- [Rust](https://rustup.rs/) 1.70+

### 编译

```bash
cargo build --release
```

编译产物位于 `target/release/smtp-analyzer`（Windows 为 `smtp-analyzer.exe`）。

## 使用

### 基本分析

```bash
smtp-analyzer analyze <pcap文件>
```

### 指定端口

```bash
smtp-analyzer analyze capture.pcap --ports 25,587,465
```

### 输出报告

```bash
# 输出 JSON 报告
smtp-analyzer analyze capture.pcap --json report.json

# 输出 CSV 报告
smtp-analyzer analyze capture.pcap --csv report.csv

# 同时输出
smtp-analyzer analyze capture.pcap --json report.json --csv report.csv
```

### 启动本地服务与 Web 页面

```bash
smtp-analyzer serve --host 127.0.0.1 --port 8080
```

启动后可直接在浏览器访问 `http://127.0.0.1:8080/`，页面支持：

- 本地选择或拖拽 `pcap / pcapng` 文件上传
- 配置 SMTP 端口列表
- 切换 Ignore VLAN 主视图
- 查看汇总指标、疑似 VLAN 不对称诊断和每条流的详情

### Smoke Test

可以用仓库内置脚本做一次本地端到端冒烟验证：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\smoke-test.ps1
```

该脚本会自动启动本地服务，检查 `/health`，再上传 `service_test_sample.pcap` 做一次分析，最后自动关闭服务进程。

### Development Checks

提交前建议至少运行以下检查：

```powershell
cargo fmt --all
cargo test
powershell -ExecutionPolicy Bypass -File .\scripts\smoke-test.ps1
```

仓库中的 GitHub Actions 也会执行同样的格式化、单元测试和冒烟验证。

### 其他选项

```
选项:
  -p, --ports <PORTS>    监控端口，逗号分隔 [默认: 25,587,465]
  -j, --json <JSON>      JSON 输出路径
  -c, --csv <CSV>        CSV 输出路径
      --ignore-vlan      忽略 VLAN 差异（将不同 VLAN 的同五元组流合并）
  -v, --verbose          详细日志输出
  -h, --help             显示帮助
```

## 输出说明

### 控制台摘要

```
=== SMTP 流量分析报告 ===
总流数: 100
完整双向: 85
完整单向: 5
不完整双向: 3
不完整单向: 7
跳过数据包: 0
```

### 异常标签

| 标签 | 说明 |
|------|------|
| `tcp_no_handshake` | TCP 三次握手不完整 |
| `tcp_midstream` | 中途接入的流（缺少 SYN） |
| `tcp_no_payload` | 无有效载荷 |
| `tcp_one_way` | 单向流量 |
| `smtp_implicit_tls` | 隐式 TLS（465 端口等） |
| `smtp_missing_banner` | 缺少服务器 Banner |
| `smtp_missing_helo` | 缺少 HELO/EHLO 命令 |
| `smtp_data_incomplete` | DATA 传输不完整 |
| `vlan_asymmetry_likely` | 严格 VLAN 视图被拆流，忽略 VLAN 后恢复为更完整的会话 |

## 项目结构

```
src/
├── main.rs       # 入口，命令行参数解析
├── app.rs        # CLI / HTTP 共用的分析入口
├── capture.rs    # pcap/pcapng 文件读取
├── decoder.rs    # 网络层解码（Ethernet / VLAN / IP / TCP）
├── flow.rs       # TCP 流重组与状态跟踪
├── analyzer.rs   # 完整性 / 双向性分析
├── model.rs      # 数据模型定义
├── report.rs     # 报告输出（JSON / CSV / 控制台）
├── service.rs    # 本地 HTTP 服务与上传接口
├── error.rs      # 错误类型定义
└── ../web/       # 内嵌的前端页面资源
```

## License

MIT
