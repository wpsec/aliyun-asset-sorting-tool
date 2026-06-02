# draw.io 拓扑图导出开发计划

## 目标

- 在现有 Mermaid 拓扑基础上，新增 `draw.io/.drawio` 导出能力。
- 输出结果可直接被 diagrams.net / draw.io 打开，不依赖运行时联网加载远程图标。
- 优先复用现有拓扑关系数据，不重复设计一套新的关系解析逻辑。
- 第一版聚焦“资源关系拓扑”，不尝试表达真实流量路径。

## 设计原则

- 保留当前 Mermaid 输出，`draw.io` 作为新增产物，不替换现有能力。
- `.drawio` 文件必须自包含，不能依赖 GitHub 在线图标库。
- 图标仅使用本次拓扑范围内需要的最小子集，避免一次性引入整库。
- 关系线只使用显式字段和确定性映射，不做名称、标签、同地域推断。
- 默认布局优先保证“可读”，不追求自动美化到最优。

## 范围

- 第一版纳入资源：
  - `VPC`
  - `VSwitch`
  - `ECS`
  - `ENI`
  - `EIP`
  - `NAT`
  - `VPN Gateway`
  - `VPN Connection`
  - `SSL-VPN`
  - `SLB`
  - `ALB`
  - `NLB`
  - `ServerGroup`
  - `Backend Server`
  - `RDS`
  - `Redis/Tair`
- 第一版不纳入资源：
  - `Disk`
  - `OSS`
  - `RAM`
  - `KMS`
  - `SLS`
  - `CEN`
  - `DNS/PrivateZone`
  - `ACK Pod/Service`
  - `CLB 后端`
- 输出范围：
  - 每个订阅一个 `topology-drawio/` 目录
  - 每个 `VPC` 一份 `.drawio`
  - 一份 `unassigned.drawio`

## 实现方案

### 1. 输出形态

- 新增 `--drawio` 开关。
- 第一版不要默认开启，先作为可选能力验证稳定性。
- 输出目录建议：
  - `outputs/<批次>/<订阅>/topology/` 保留 Mermaid
  - `outputs/<批次>/<订阅>/topology-drawio/` 输出 `.drawio`
- 每个 `.drawio` 文件只包含一个页面，便于打开和编辑。
- 文件命名规则与 Mermaid 保持一致：
  - `<region>__<vpc-id>.drawio`
  - `unassigned.drawio`

### 2. 数据复用

- 复用现有 `build_topology_documents` 之前的拓扑归类逻辑。
- 抽出统一的“拓扑中间模型”层，避免 Mermaid 和 draw.io 各自重复构图。
- 中间模型至少包含：
  - 节点列表
  - 边列表
  - 节点类型
  - 节点标签
  - 所属 `VPC`
  - 所属 `VSwitch`
  - 是否未归属
  - 采集异常摘要
- Mermaid 和 draw.io 都从同一个中间模型渲染。

### 3. 图标资源

- 使用 `mcsrainbow/alibaba-cloud-icons` 作为图标来源参考。
- 运行时不从 GitHub 拉取资源。
- 仓库内新增最小图标子集目录，建议只引入本期用到的 SVG。
- 图标命名使用统一映射键，例如：
  - `vpc`
  - `vswitch`
  - `ecs`
  - `eni`
  - `eip`
  - `nat`
  - `vpn_gateway`
  - `vpn_connection`
  - `ssl_vpn`
  - `slb`
  - `alb`
  - `nlb`
  - `server_group`
  - `rds`
  - `redis`
- 未命中图标时使用通用矩形节点回退，不允许导出失败。

### 4. draw.io 生成

- 直接生成 `.drawio` XML，不依赖第三方 Python 库。
- 采用固定布局策略：
  - `VPC` 作为最外层容器
  - `VSwitch` 作为内层容器
  - `ECS / ENI / RDS / Redis` 优先放入 `VSwitch`
  - `EIP / NAT / VPN / LB / ServerGroup` 放在 `VPC` 层
  - `Listener` 放在对应 `LB` 下方
  - `Backend Server` 连到 `ServerGroup`
- 节点样式分两类：
  - 图标节点
  - 容器节点
- 连线统一使用直角线或简化折线，不做复杂自动避让。
- 页面顶部增加说明文本：
  - 只基于显式关系生成
  - 不代表真实流量路径
  - 如果存在采集失败，列出关键接口失败摘要

### 5. 参数与主流程

- `--drawio` 依赖详情采集。
- `--drawio` 与 `--no-detail` 互斥。
- `--checks-only` 可以生成 draw.io，只要已有底稿且能补采详情。
- `--verify-only` 不生成 draw.io。
- 控制台输出新增：
  - `拓扑Drawio=<路径>`

## 测试计划

- 新增单测覆盖：
  - `VPC + VSwitch + ECS + EIP` 基础布局与连线正确
  - `ALB/NLB + Listener + ServerGroup + Backend` 正确成链
  - `RDS/Redis` 无法确认归属时进入 `unassigned.drawio`
  - `--drawio --no-detail` 返回参数错误
  - 图标缺失时能回退到通用节点
  - 关键接口失败时 `.drawio` 仍生成且包含缺失说明
- 保持现有 Mermaid 测试不回归。
- 保持现有 `unittest` 全量通过。

## 验收标准

- 执行带 `--drawio` 的导出命令后，每个订阅目录都能看到 `topology-drawio/`。
- `.drawio` 文件可直接用 diagrams.net 打开。
- 至少能正确展示 `VPC / VSwitch / ECS / EIP / LB / ServerGroup / Backend / RDS / Redis`。
- 无网络环境下仍可正常导出。
- 未命中图标、采集失败、资源未归属三类情况都有可读回退。
- 不影响现有 CSV、Excel、Mermaid 输出。

## 风险与待确认项

- 需要确认 `alibaba-cloud-icons` 的授权边界，决定是否可直接随仓库分发图标子集。
- `.drawio` XML 结构比 Mermaid 更复杂，建议第一版只做固定布局，不做自动重排。
- 如果后续要默认输出 draw.io，再评估输出体积、生成耗时和可维护性。

## 建议开发顺序

- 第一步：抽出拓扑中间模型
- 第二步：接入本地图标映射和回退样式
- 第三步：生成单页 `.drawio` XML
- 第四步：接主流程参数和输出路径
- 第五步：补文档和测试
- 第六步：用真实账号样本做一次冒烟验证
