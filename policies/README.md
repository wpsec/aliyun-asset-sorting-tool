# RAM 只读策略

本目录保存资产梳理 RAM 自定义策略。创建策略时建议使用文件名去掉 `.json` 后的内容作为策略名称。

需要全部绑定到同一个资产梳理 RAM 用户或 RAM 角色：

- `list-resourcecenter-resourcemanager-resourcesharing-tag-ram-config-actiontrail.json`
- `list-ecs-cs-cr-eci.json`
- `list-vpc-slb-alb-nlb-cen-ga-cdn-dcdn-dns-pvtz.json`
- `list-rds-polardb-kvstore-dds-adb-hbase-oss-nas-ebs.json`
- `list-cms-arms-log-kms-sas-cloudfw-waf-bastionhost-pam.json`

策略原则：

- 不使用 Action 通配符。
- 不授予写入、删除、启停、授权、执行命令类动作。
- 不授予 OSS Object 内容、SLS 日志正文、KMS 凭据值、ACK kubeconfig、ACR Token 等敏感读取动作。
- `Resource` 保留 `"*"`，用于支持跨地域、账号级和列表类资产发现。

