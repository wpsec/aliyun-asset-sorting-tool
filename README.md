# 阿里云云资产梳理工具

本项目用于通过阿里云 RAM 只读策略和 `aliyun` CLI 梳理云资产，输出原始资源中心清单和可交付 Excel 报告。

## 目录结构

```text
.
├── aliyun_asset_inventory.py         # 项目根目录入口
├── policies/                         # RAM 自定义策略 JSON
├── checks/                           # 日常运维巡检规则
├── scripts/aliyun_asset_inventory.py # 资产梳理脚本
├── config/checks.example.json        # 巡检阈值配置示例
├── config/subscriptions.example.csv  # 多订阅配置示例
├── docs/策略说明.md                  # 策略边界和使用说明
└── outputs/                          # 默认输出目录
```

## 安全边界

- 不在脚本、配置示例、README 中写入 AK/SK。
- 脚本只读取 `aliyun` CLI profile 名称，凭据由 `~/.aliyun/config.json` 管理。
- RAM 策略不使用 Action 通配符，不包含 Deny，不授予创建、修改、删除、启停、授权、执行命令、读取对象内容、读取日志正文、读取密钥明文等权限。
- 专用 RAM 用户或角色只建议绑定 `policies/` 下的 5 份策略，不叠加 `AdministratorAccess`、`*FullAccess` 或宽泛系统只读策略。

## 策略文件

需要在 RAM 中分别创建 5 个自定义策略，并全部绑定到同一个资产梳理 RAM 用户或角色：

| 文件 | 覆盖范围 |
| --- | --- |
| `policies/list-resourcecenter-resourcemanager-resourcesharing-tag-ram-config-actiontrail.json` | 资源中心、资源目录、资源共享、标签、RAM、配置审计、操作审计 |
| `policies/list-ecs-cs-cr-eci.json` | ECS、ACK、ACR、ECI |
| `policies/list-vpc-slb-alb-nlb-cen-ga-cdn-dcdn-dns-pvtz.json` | VPC、SLB、ALB、NLB、CEN、GA、CDN、DCDN、DNS、PrivateZone |
| `policies/list-rds-polardb-kvstore-dds-adb-hbase-oss-nas-ebs.json` | RDS、PolarDB、Redis/Tair、MongoDB、ADB、HBase、OSS、NAS、EBS |
| `policies/list-cms-arms-log-kms-sas-cloudfw-waf-bastionhost-pam.json` | 云监控、ARMS、SLS 元数据、KMS 元数据、云安全中心、云防火墙、WAF、堡垒机 |

详细说明见 [docs/策略说明.md](docs/策略说明.md)。

## 凭据配置

先在本机配置一个或多个 `aliyun` CLI profile：

```bash
aliyun configure --mode AK --profile dev资产梳理
aliyun configure --mode AK --profile prod资产梳理
```

不要把 AK/SK 写进命令参数、脚本、README 或订阅配置文件。

## 权限验证

单订阅验证：

```bash
python3 aliyun_asset_inventory.py --profile dev资产梳理 --verify-only
```

多订阅验证：

```bash
python3 aliyun_asset_inventory.py --profiles dev资产梳理,prod资产梳理 --verify-only
```

## 导出报告

冒烟测试，先导出少量资源：

```bash
python3 aliyun_asset_inventory.py --profile dev资产梳理 --verify --limit 20 --output-dir outputs/smoke
```

多订阅全量导出：

```bash
python3 aliyun_asset_inventory.py --profiles dev资产梳理,prod资产梳理 --output-dir outputs/aliyun-assets
```

使用订阅配置文件：

```bash
python3 aliyun_asset_inventory.py --subscription-file config/subscriptions.example.csv --output-dir outputs/aliyun-assets
```

默认会执行静态日常运维巡检，并把巡检结果写入 Excel。只导出资产、不做巡检：

```bash
python3 aliyun_asset_inventory.py --profile dev资产梳理 --no-checks
```

复用已有底稿，只重新生成巡检结果和报告：

```bash
python3 aliyun_asset_inventory.py --profile dev资产梳理 --checks-only --output-dir outputs/aliyun-assets
```

使用自定义巡检阈值：

```bash
python3 aliyun_asset_inventory.py \
  --profile dev资产梳理 \
  --checks-config config/checks.example.json \
  --severity-threshold medium
```

输出示例：

```text
outputs/aliyun-assets/
├── dev资产梳理/
│   ├── raw-resourcecenter.csv
│   ├── findings.csv
│   └── asset-report.xlsx
├── prod资产梳理/
│   ├── raw-resourcecenter.csv
│   ├── findings.csv
│   └── asset-report.xlsx
├── all-subscriptions.csv
├── all-subscriptions-findings.csv
└── all-subscriptions-report.xlsx
```

## Excel 报告内容

`asset-report.xlsx` 默认包含：

- `报告说明`
- `总览统计`
- `采集问题`
- `巡检总览`
- `巡检明细`
- `闲置资源`
- `未使用配置`
- `高风险暴露`
- `指标疑似闲置`
- `ECS云服务器`
- `ECS磁盘`
- `ECS安全组`
- `ECS快照`
- `网络与负载均衡`
- `数据库`
- `存储`
- `容器`
- `漏洞修复命令`
- `安全监控`
- `全部资源`

脚本会保留资源中心原始发现结果，并额外调用 ECS、VPC、SLB/ALB/NLB、RAM、OSS、云安全中心等只读接口补充巡检和漏洞修复命令所需的元数据。ECS 云服务器表会包含实例名称、实例 ID、状态、规格、CPU、内存、操作系统、镜像、VPC、交换机、私网 IP、公网 IP、EIP、安全组、付费类型、创建时间、到期时间、标签等字段。

巡检结果只输出发现和建议，不自动修复，不修改云资源。第一版覆盖静态巡检项：

- ECS：未挂载云盘、已停止实例、未绑定安全组、安全组公网开放高危端口、云盘未关联自动快照策略。
- VPC：空 VPC、空交换机、未绑定 EIP、无 SNAT/DNAT 的 NAT 网关、无 IPsec/SSL 配置的 VPN 网关。
- SLB/ALB/NLB：无监听负载均衡、无后端服务器的服务器组、公网负载均衡未发现 HTTPS/TLS 监听。
- RAM：长期未使用 AK、未启用 MFA 的 RAM 用户、空用户组。
- OSS：Bucket 未开启服务端加密、Bucket 公开访问风险、Bucket 未配置生命周期。
- 数据库：RDS 或 Redis/Tair 存在公网连接地址。
- 云监控：可选启用，ECS、EIP、SLB、RDS、Redis/Tair 近 7/14/30 天低使用率时标记为“疑似闲置”。

指标类巡检只输出“疑似闲置”，不代表资源可以直接删除，仍需结合业务窗口、负责人和监控告警人工确认。
指标巡检默认关闭，因为它会增加大量云监控 API 调用；需要排查低使用率时，可以在 `config/checks.example.json` 中把 `指标巡检.启用` 设为 `true` 后再执行。

巡检发现会同时输出到 `findings.csv`，字段包含风险等级、整改优先级、检查项 ID、发现结果、建议动作和证据，便于导入工单、审计平台或 CMDB。

巡检结果会额外输出 `计费属性` 和 `计费说明`：

- `持续计费`：ECS、云盘、EIP、NAT、VPN、负载均衡、数据库等，闲置时优先复核成本。
- `用量计费`：OSS、SLS 等，资源存在不一定代表持续扣费，需要结合存储量、请求、流量、索引等用量。
- `通常不直接计费`：VPC、交换机、安全组、RAM 身份等，更偏配置治理或安全治理。
- `需账单确认`：仅凭资产元数据无法判断，最终以费用与成本账单明细为准。

报告中的云服务会展示为 `服务码（中文资产名称）`，例如：

- `cr（容器镜像服务）`
- `ecs（云服务器）`
- `eip（弹性公网IP）`
- `kms（密钥管理服务）`
- `nas（文件存储NAS）`
- `nat（NAT网关）`
- `oss（对象存储）`
- `privatezone（PrivateZone）`
- `pvtz（PrivateZone）`
- `ram（访问控制）`
- `rds（云数据库RDS）`
- `redis（Redis/Tair）`
- `kvstore（Redis/Tair）`
- `slb（传统型负载均衡）`
- `log（日志服务）`
- `sls（日志服务）`
- `vpc（专有网络）`
- `vpn（VPN）`

EIP、NAT、VPN 在阿里云资源中心里通常归属于 VPC 服务，在报告中也会通过资产类型展示为 `弹性公网IP`、`NAT网关`、`VPN网关` 或 `VPN连接`。

## 常用参数

| 参数 | 说明 |
| --- | --- |
| `--profiles` | 多个 profile，用英文逗号分隔 |
| `--subscription` | 单个订阅配置，格式 `profile,输出目录名,scope` |
| `--subscription-file` | 订阅配置文件，每行一个 `profile,输出目录名,scope` |
| `--output-dir` | 输出目录 |
| `--verify-only` | 只做权限验证 |
| `--verify` | 导出前先做权限验证 |
| `--limit` | 限制导出资源数量，适合冒烟测试 |
| `--no-raw-csv` | 不输出原始 CSV |
| `--no-report` | 不输出 Excel 报告 |
| `--no-detail` | 不调用 ECS 详情接口，只用资源中心数据生成报告 |
| `--no-checks` | 不执行日常运维巡检 |
| `--checks-only` | 复用已有 `raw-resourcecenter.csv`，仅重新生成巡检结果和报告 |
| `--checks-config` | 指定巡检阈值配置文件 |
| `--severity-threshold` | 巡检报告最低风险等级：`low`、`medium`、`high` |
| `--findings-output` | 单订阅巡检发现 CSV 输出路径 |

无论从项目根目录还是 `scripts/` 目录执行，默认输出目录都会固定到项目根目录的 `outputs/`。相对路径参数，例如 `--output-dir outputs/smoke`、`--checks-config config/checks.example.json`，也会按项目根目录解析。

## 巡检白名单

可以在 `config/checks.example.json` 中配置白名单，减少保留盘、预留 EIP、模板安全组等已知资源的误报。示例配置已支持中文字段，同时兼容旧版英文字段。白名单支持三种方式：

- `资源ID`：按资源 ID 跳过。
- `资源组ID`：按资源组跳过。
- `标签`：按标签键值跳过，标签值可用 `*` 表示任意值。

详细规则见 [docs/巡检项说明.md](docs/巡检项说明.md)。
