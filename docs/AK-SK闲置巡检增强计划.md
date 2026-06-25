# AK/SK 闲置巡检增强计划

## 背景

当前 `ram_stale_access_key` 仅覆盖 RAM 子用户的 Active 状态 AK，阈值单一（默认 90 天），无法区分 Root AK 与子用户 AK、无法评估 AK 权限级别与闲置时长叠加风险、不支持分级阈值（如 30/90/180 天对应不同严重度）。

## 现状分析

| 维度 | 当前覆盖 | 短板 |
| --- | --- | --- |
| 检查对象 | RAM 子用户 AK | 未覆盖 Root 账号 AK |
| 状态过滤 | 仅 Active | Inactive AK 仍存在泄露风险，未提示清理 |
| 阈值 | 单一天数（90d） | 无分级，30d 与 180d 同一严重度 |
| 权限关联 | 无 | 无法区分"闲置+高权限"与"闲置+低权限"的风险差异 |
| AK 轮转 | 无 | 仅看最后使用时间，未看 AK 自创建以来的服役时长 |
| 证据 | 用户名 + 脱敏 AK + 时间 | 缺少权限摘要、绑定策略数量等辅助判断信息 |

## 目标

1. Root 账号存在 Active AK 即报高危，不依赖闲置天数。
2. 子用户 AK 闲置天数分级：30d（低）/ 90d（中）/ 180d（高）。
3. AK 创建超过 1 年未轮转，作为单独巡检项提示。
4. 闲置 AK 绑定高危策略（AdministratorAccess / 超过 N 条策略）叠加升级严重度。
5. Inactive AK 存在超过阈值天数，提示建议删除。
6. 证据字段补充权限摘要信息，便于人工复核。

## 巡检项设计

### 1. `ram_root_access_key` — Root 账号 AccessKey 存在

| 属性 | 值 |
| --- | --- |
| 严重度 | 高 |
| 分类 | 高风险暴露 |
| 阈值 | 无阈值，Root 账号存在 Active AK 即报 |
| 证据 | AK 脱敏 ID、状态、创建时间、最后使用时间 |
| 建议 | Root 账号不应持有 AK；建议禁用并删除，日常操作使用 RAM 子用户 + MFA |

**数据获取**：调用 `ram ListAccessKeys`（不传 `--UserName`），返回的是主账号 AK 列表。当前 `collect_ram_details` 仅遍历 RAM 子用户，需新增 Root AK 采集逻辑。

### 2. `ram_stale_access_key` — AK 分级闲置（增强现有）

| 属性 | 值 |
| --- | --- |
| 严重度 | 低（30-89d）/ 中（90-179d）/ 高（>=180d） |
| 分类 | 未使用配置 |
| 阈值 | `stale_access_key_days` 仍为基线（默认 90），分级通过 `stale_access_key_severe_days`（默认 180）和 `stale_access_key_warn_days`（默认 30）配置 |
| 证据 | 用户名、AK 脱敏 ID、最后使用时间、创建时间、闲置天数、权限摘要 |
| 建议 | 按严重度分级建议：低->观察；中->禁用后观察再删除；高->立即禁用 |

**权限摘要**：统计该 RAM 用户绑定策略数，如果包含 `AdministratorAccess` 或策略数 >= 阈值，严重度升一级。

### 3. `ram_access_key_rotation` — AK 长期未轮转

| 属性 | 值 |
| --- | --- |
| 严重度 | 中 |
| 分类 | 身份安全 |
| 阈值 | `access_key_rotation_days`，默认 365 |
| 证据 | 用户名、AK 脱敏 ID、创建时间、服役天数、最后使用时间 |
| 建议 | AK 创建超过一年未轮转；建议创建新 AK -> 替换应用配置 -> 禁用旧 AK -> 观察后删除 |

**逻辑**：不论 AK 是否闲置，只要 Active 且创建时间超过 `rotation_days`，即纳入。与 `ram_stale_access_key` 互补——一个看"是否还在用"，一个看"用了多久没换"。

### 4. `ram_inactive_access_key_cleanup` — Inactive AK 长期残留

| 属性 | 值 |
| --- | --- |
| 严重度 | 低 |
| 分类 | 未使用配置 |
| 阈值 | `inactive_access_key_cleanup_days`，默认 90 |
| 证据 | 用户名、AK 脱敏 ID、状态、创建时间、禁用时长 |
| 建议 | AK 已禁用超过阈值天数，泄露风险虽降低但仍存在；建议确认无依赖后删除 |

**逻辑**：检查 Status=Inactive 的 AK，计算 `(now - last_used_date or create_date)` 超过阈值即纳入。Inactive AK 虽不可调用但 AK 前缀仍在系统中，社工/泄露场景仍有风险。

## 实施步骤

### 第一阶段：数据采集层

1. **Root AK 采集** — 在 `collect_ram_details` 中，遍历子用户前先调用 `ram ListAccessKeys`（无 UserName 参数）获取主账号 AK 列表，调用 `GetAccessKeyLastUsed` 补充使用信息。
2. **RAM 用户策略采集** — 为每个 RAM 子用户调用 `ram ListPoliciesForUser`，采集策略名与策略数量。存入 `details.ram_user_policies`。
3. **DetailedAssets 新增字段**：
   - `ram_root_access_keys: list[dict]`
   - `ram_user_policies: list[dict]`
4. **normalize 函数**：
   - `normalize_root_access_key`
   - `normalize_ram_user_policy`

### 第二阶段：配置层

`ChecksConfig` 新增：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `stale_access_key_warn_days` | int | 30 | AK 闲置低风险阈值 |
| `stale_access_key_severe_days` | int | 180 | AK 闲置高风险阈值 |
| `access_key_rotation_days` | int | 365 | AK 轮转阈值 |
| `inactive_access_key_cleanup_days` | int | 90 | Inactive AK 清理阈值 |
| `high_privilege_policy_names` | set[str] | {"AdministratorAccess"} | 触发严重度升级的策略名 |
| `high_privilege_policy_count` | int | 10 | 触发严重度升级的策略数量阈值 |

`enabled` 默认值新增：

```python
"ram_root_access_key": True,
"ram_access_key_rotation": True,
"ram_inactive_access_key_cleanup": True,
```

`ChecksConfig.from_file` 解析对应中文/英文配置项。

### 第三阶段：巡检规则层

`checks/ram.py` 新增：

- `check_root_access_keys(context)` — Root AK 存在即报高危
- `check_stale_access_keys(context)` — 重构为分级闲置，叠加权限升级
- `check_access_key_rotation(context)` — AK 创建超过轮转阈值
- `check_inactive_access_key_cleanup(context)` — Inactive AK 残留清理

`checks/ram.py` 的 `run()` 函数扩展调用上述新增函数。

### 第四阶段：测试与文档

1. `tests/test_checks.py` 新增覆盖所有新巡检项的单元测试。
2. 更新 `docs/巡检项说明.md` 新增四个巡检项描述。
3. 更新 `config/checks.example.json` 新增配置示例。
4. 更新 README 中巡检命令示例（如涉及新参数）。

## 优先级排序

| 序号 | 巡检项 | 优先级 | 原因 |
| --- | --- | --- | --- |
| 1 | `ram_root_access_key` | P0 | Root AK 是最严重的安全风险，零阈值即报 |
| 2 | `ram_stale_access_key` 分级增强 | P1 | 当前已有基础逻辑，分级改造成本低 |
| 3 | `ram_inactive_access_key_cleanup` | P2 | Inactive AK 残留是低优先级治理项 |
| 4 | `ram_access_key_rotation` | P2 | 轮转需要应用配合，巡检提示优先 |

## API 调用估算

每个订阅新增 API 调用：

| API | 调用次数 | 说明 |
| --- | --- | --- |
| `ram ListAccessKeys`（无 UserName） | 1 | Root AK 列表 |
| `ram GetAccessKeyLastUsed` | N（Root AK 数） | Root AK 使用信息 |
| `ram ListPoliciesForUser` | M（RAM 子用户数） | 用户策略列表 |

假设单订阅 10 个 RAM 用户、2 个 Root AK，新增约 22 次 API 调用。资源量较大时影响可控。

## 风险与注意事项

1. **Root AK 查询**：部分企业主账号可能因权限配置无法查询自身 AK，需在 `collection_events` 中记录查询失败。
2. **策略数量**：`ListPoliciesForUser` 仅返回直接授权策略，不含继承自组的策略。如需完整权限视图需额外调用 `ListPoliciesForGroup` + 组成员关系，本阶段暂不做。
3. **分级阈值默认值**：30/90/180 天为推荐值，不同企业安全基线差异大，配置化是关键。
4. **严重度升级**：权限叠加升级只在 `ram_stale_access_key` 中生效，Root AK 和轮转项不受权限升级影响（Root 本身已是最高风险，轮转属于时间维度风险）。
