import dataclasses
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from checks import CheckContext, ChecksConfig, finding_rows, run_checks


def make_details(**overrides):
    base = {
        "ecs_instances": [],
        "ecs_disks": [],
        "ecs_security_groups": [],
        "ecs_network_interfaces": [],
        "ecs_security_group_rules": [],
        "vpc_eips": [],
        "vpc_nat_gateways": [],
        "vpc_snat_entries": [],
        "vpc_dnat_entries": [],
        "vpc_vpn_gateways": [],
        "vpc_vpn_connections": [],
        "vpc_ssl_vpn_servers": [],
        "slb_load_balancers": [],
        "slb_listeners": [],
        "alb_load_balancers": [],
        "alb_listeners": [],
        "alb_server_groups": [],
        "alb_server_group_servers": [],
        "nlb_load_balancers": [],
        "nlb_listeners": [],
        "nlb_server_groups": [],
        "nlb_server_group_servers": [],
        "ram_users": [],
        "ram_access_keys": [],
        "ram_root_access_keys": [],
        "ram_user_policies": [],
        "ram_user_mfa": [],
        "ram_groups": [],
        "ram_group_users": [],
        "oss_buckets": [],
        "ecs_snapshot_policy_associations": [],
        "rds_instances": [],
        "rds_net_infos": [],
        "rds_ip_arrays": [],
        "redis_instances": [],
        "redis_net_infos": [],
        "metric_summaries": [],
        "collection_events": [],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def run_with(details, raw_rows=None, config=None):
    context = CheckContext(
        raw_rows=raw_rows or [],
        details=details,
        config=config or ChecksConfig.default(),
        now=dt.datetime(2026, 5, 7, tzinfo=dt.timezone.utc),
    )
    return run_checks(context)


class CheckRulesTest(unittest.TestCase):
    def test_unused_ecs_disk(self):
        findings = run_with(
            make_details(
                ecs_disks=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "disk_id": "d-001",
                        "disk_name": "data-unused",
                        "status": "Available",
                        "size_gb": "100",
                    }
                ]
            )
        )
        self.assertIn("ecs_unused_disk", {item.check_id for item in findings})

    def test_unused_eip(self):
        findings = run_with(
            make_details(
                vpc_eips=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "allocation_id": "eip-001",
                        "ip_address": "203.0.113.10",
                        "status": "Available",
                    }
                ]
            )
        )
        self.assertIn("vpc_unused_eip", {item.check_id for item in findings})

    def test_public_high_risk_security_group_rule(self):
        findings = run_with(
            make_details(
                ecs_security_group_rules=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "security_group_id": "sg-001",
                        "source_cidr_ip": "0.0.0.0/0",
                        "port_range": "22/22",
                        "policy": "Accept",
                        "direction": "ingress",
                        "ip_protocol": "tcp",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ecs_high_risk_security_group_rule"]
        self.assertEqual("high", matched[0].severity)

    def test_public_icmp_security_group_rule_is_not_high_risk(self):
        findings = run_with(
            make_details(
                ecs_security_group_rules=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "security_group_id": "sg-001",
                        "source_cidr_ip": "0.0.0.0/0",
                        "port_range": "-1/-1",
                        "policy": "Accept",
                        "direction": "ingress",
                        "ip_protocol": "icmp",
                    }
                ]
            )
        )
        self.assertNotIn(
            "ecs_high_risk_security_group_rule",
            {item.check_id for item in findings},
        )

    def test_trusted_internal_security_group_rule_is_not_high_risk(self):
        findings = run_with(
            make_details(
                ecs_security_group_rules=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "security_group_id": "sg-001",
                        "source_cidr_ip": "192.168.20.0/23",
                        "port_range": "22/22",
                        "policy": "Accept",
                        "direction": "ingress",
                        "ip_protocol": "tcp",
                    }
                ]
            )
        )
        self.assertNotIn(
            "ecs_high_risk_security_group_rule",
            {item.check_id for item in findings},
        )

    def test_stale_access_key(self):
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "asset-user",
                        "access_key_id": "LTAI000000001234",
                        "status": "Active",
                        "create_date": "2025-01-01T00:00:00Z",
                        "last_used_date": "2025-01-05T00:00:00Z",
                    }
                ]
            )
        )
        self.assertIn("ram_stale_access_key", {item.check_id for item in findings})

    def test_public_rds_endpoint_without_whitelist_is_reported(self):
        findings = run_with(
            make_details(
                rds_net_infos=[
                    {
                        "subscription": "uat",
                        "account_id": "1671544939861873",
                        "region_id": "cn-shanghai",
                        "instance_id": "pgm-001",
                        "resource_id": "pgm-001",
                        "resource_name": "ctp-uat-pgsql",
                        "net_type": "Public",
                        "connection_string": "pgm-001fo.pg.rds.aliyuncs.com",
                        "port": "5432",
                    }
                ]
            )
        )
        self.assertIn("rds_public_endpoint", {item.check_id for item in findings})

    def test_public_rds_endpoint_with_restricted_whitelist_is_not_reported(self):
        findings = run_with(
            make_details(
                rds_net_infos=[
                    {
                        "subscription": "uat",
                        "account_id": "1671544939861873",
                        "region_id": "cn-shanghai",
                        "instance_id": "pgm-001",
                        "resource_id": "pgm-001",
                        "resource_name": "ctp-uat-pgsql",
                        "net_type": "Public",
                        "connection_string": "pgm-001fo.pg.rds.aliyuncs.com",
                        "port": "5432",
                    }
                ],
                rds_ip_arrays=[
                    {
                        "subscription": "uat",
                        "account_id": "1671544939861873",
                        "region_id": "cn-shanghai",
                        "instance_id": "pgm-001",
                        "resource_id": "pgm-001",
                        "resource_name": "ctp-uat-pgsql",
                        "whitelist_name": "default",
                        "whitelist_attribute": "",
                        "security_ip_list": "172.16.15.0/24",
                        "security_ip_type": "IPv4",
                    },
                    {
                        "subscription": "uat",
                        "account_id": "1671544939861873",
                        "region_id": "cn-shanghai",
                        "instance_id": "pgm-001",
                        "resource_id": "pgm-001",
                        "resource_name": "ctp-uat-pgsql",
                        "whitelist_name": "eyti_office",
                        "whitelist_attribute": "",
                        "security_ip_list": "58.246.209.211",
                        "security_ip_type": "IPv4",
                    },
                ],
            )
        )
        self.assertNotIn(
            "rds_public_endpoint",
            {item.check_id for item in findings},
        )

    def test_public_rds_endpoint_with_open_whitelist_is_reported(self):
        findings = run_with(
            make_details(
                rds_net_infos=[
                    {
                        "subscription": "uat",
                        "account_id": "1671544939861873",
                        "region_id": "cn-shanghai",
                        "instance_id": "pgm-001",
                        "resource_id": "pgm-001",
                        "resource_name": "ctp-uat-pgsql",
                        "net_type": "Public",
                        "connection_string": "pgm-001fo.pg.rds.aliyuncs.com",
                        "port": "5432",
                    }
                ],
                rds_ip_arrays=[
                    {
                        "subscription": "uat",
                        "account_id": "1671544939861873",
                        "region_id": "cn-shanghai",
                        "instance_id": "pgm-001",
                        "resource_id": "pgm-001",
                        "resource_name": "ctp-uat-pgsql",
                        "whitelist_name": "default",
                        "whitelist_attribute": "",
                        "security_ip_list": "0.0.0.0/0",
                        "security_ip_type": "IPv4",
                    }
                ],
            )
        )
        self.assertIn("rds_public_endpoint", {item.check_id for item in findings})

    def test_normal_resources_have_no_findings(self):
        findings = run_with(
            make_details(
                ecs_instances=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "instance_id": "i-001",
                        "status": "Running",
                        "security_group_ids": "sg-001",
                        "vpc_id": "vpc-001",
                        "vswitch_id": "vsw-001",
                    }
                ],
                ecs_disks=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "disk_id": "d-001",
                        "status": "In_use",
                        "instance_id": "i-001",
                    }
                ],
                ecs_security_groups=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "security_group_id": "sg-001",
                    }
                ],
                ecs_snapshot_policy_associations=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "disk_id": "d-001",
                    }
                ],
            )
        )
        self.assertEqual([], findings)

    def test_whitelisted_resource_is_skipped(self):
        config = ChecksConfig.default()
        config = dataclasses.replace(
            config,
            whitelist_resource_ids={"d-001"},
        )
        findings = run_with(
            make_details(
                ecs_disks=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "disk_id": "d-001",
                        "status": "Available",
                    }
                ]
            ),
            config=config,
        )
        self.assertEqual([], findings)

    def test_chinese_checks_config_is_supported(self):
        data = {
            "高危端口": [1234],
            "访问密钥未使用天数阈值": 30,
            "白名单": {
                "资源ID": ["d-001"],
                "资源组ID": ["rg-001"],
                "标签": [{"键": "keep", "值": "*"}],
            },
            "指标巡检": {
                "启用": False,
                "统计窗口天数": [14],
                "采样周期秒": 300,
                "阈值": {"ECS平均CPU百分比": 5},
            },
            "启用巡检项": {
                "未挂载云盘": False,
                "ECS低使用率疑似闲置": False,
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "checks.json"
            path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            config = ChecksConfig.from_file(path, "low")

        self.assertEqual({1234}, config.high_risk_ports)
        self.assertEqual(30, config.stale_access_key_days)
        self.assertEqual({"d-001"}, config.whitelist_resource_ids)
        self.assertEqual({"rg-001"}, config.whitelist_resource_group_ids)
        self.assertEqual({"keep": {"*"}}, config.whitelist_tags)
        self.assertFalse(config.metric_checks_enabled)
        self.assertEqual([14], config.metric_windows_days)
        self.assertEqual(300, config.metric_period_seconds)
        self.assertEqual(5.0, config.metric_thresholds["ecs_cpu_avg_percent"])
        self.assertFalse(config.is_enabled("ecs_unused_disk"))
        self.assertFalse(config.is_enabled("metric_idle_ecs"))

    def test_empty_vswitch_is_not_billing_priority(self):
        findings = run_with(
            make_details(),
            raw_rows=[
                {
                    "subscription": "dev",
                    "account_id": "1001",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-f",
                    "service_code": "vpc",
                    "resource_type": "ACS::VPC::VSwitch",
                    "resource_id": "vsw-001",
                    "resource_name": "reserved-switch",
                }
            ],
        )
        rows = finding_rows(findings)
        matched = [row for row in rows if row["check_id"] == "vpc_empty_vswitch"]
        self.assertEqual("P3-一般优化", matched[0]["remediation_priority"])
        self.assertEqual("通常不直接计费", matched[0]["billing_attribute"])

    def test_unused_disk_has_billing_context(self):
        findings = run_with(
            make_details(
                ecs_disks=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "disk_id": "d-001",
                        "status": "Available",
                    }
                ]
            )
        )
        rows = finding_rows(findings)
        matched = [row for row in rows if row["check_id"] == "ecs_unused_disk"]
        self.assertEqual("P1-闲置计费资源", matched[0]["remediation_priority"])
        self.assertEqual("持续计费", matched[0]["billing_attribute"])

    def test_vpn_gateway_with_ssl_server_is_not_unused(self):
        findings = run_with(
            make_details(
                vpc_vpn_gateways=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "vpn_gateway_id": "vpn-001",
                        "resource_name": "ssl-vpn",
                        "status": "active",
                    }
                ],
                vpc_ssl_vpn_servers=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "ssl_vpn_server_id": "vss-001",
                        "vpn_gateway_id": "vpn-001",
                    }
                ],
            )
        )
        self.assertNotIn("vpc_vpn_without_connection", {item.check_id for item in findings})

    def test_metric_idle_ecs(self):
        config = dataclasses.replace(ChecksConfig.default(), metric_checks_enabled=True)
        findings = run_with(
            make_details(
                metric_summaries=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "resource_id": "i-001",
                        "resource_name": "web-01",
                        "check_id": "metric_idle_ecs",
                        "metric_role": "ecs_cpu",
                        "window_days": "30",
                        "average": "1.5",
                        "maximum": "2.0",
                        "datapoints": "30",
                    },
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "resource_id": "i-001",
                        "resource_name": "web-01",
                        "check_id": "metric_idle_ecs",
                        "metric_role": "ecs_network_out",
                        "window_days": "30",
                        "average": "10",
                        "maximum": "20",
                        "datapoints": "30",
                    },
                ]
            ),
            config=config,
        )
        self.assertIn("metric_idle_ecs", {item.check_id for item in findings})

    def test_root_access_key_active(self):
        findings = run_with(
            make_details(
                ram_root_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "root",
                        "resource_id": "root",
                        "resource_name": "root",
                        "access_key_id": "LTAI000000005678",
                        "status": "Active",
                        "create_date": "2025-06-01T00:00:00Z",
                        "last_used_date": "2025-12-01T00:00:00Z",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ram_root_access_key"]
        self.assertTrue(len(matched) > 0)
        self.assertEqual("high", matched[0].severity)

    def test_root_access_key_inactive_not_reported(self):
        findings = run_with(
            make_details(
                ram_root_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "root",
                        "resource_id": "root",
                        "resource_name": "root",
                        "access_key_id": "LTAI000000005678",
                        "status": "Inactive",
                        "create_date": "2025-06-01T00:00:00Z",
                        "last_used_date": "",
                    }
                ]
            )
        )
        self.assertNotIn("ram_root_access_key", {item.check_id for item in findings})

    def test_access_key_no_usage_record(self):
        # Active AK 无 last_used_date，创建超过 30 天，应触发 no_usage_record 检查
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "unknown-usage-user",
                        "access_key_id": "LTAI000000009999",
                        "status": "Active",
                        "create_date": "2025-01-01T00:00:00Z",
                        "last_used_date": "",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ram_access_key_no_usage_record"]
        self.assertTrue(len(matched) > 0)
        self.assertEqual("low", matched[0].severity)

    def test_access_key_no_usage_record_not_reported_when_has_last_used(self):
        # Active AK 有 last_used_date 数据，不应触发 no_usage_record
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "has-usage-user",
                        "access_key_id": "LTAI000000001000",
                        "status": "Active",
                        "create_date": "2025-01-01T00:00:00Z",
                        "last_used_date": "2025-06-01T00:00:00Z",
                    }
                ]
            )
        )
        self.assertNotIn("ram_access_key_no_usage_record", {item.check_id for item in findings})

    def test_stale_access_key_low_severity(self):
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "low-risk-user",
                        "access_key_id": "LTAI000000001111",
                        "status": "Active",
                        "create_date": "2025-12-01T00:00:00Z",
                        "last_used_date": "2026-03-23T00:00:00Z",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ram_stale_access_key"]
        self.assertTrue(len(matched) > 0)
        self.assertEqual("low", matched[0].severity)

    def test_stale_access_key_medium_severity(self):
        # 闲置约 100 天，落在 90-179 天区间，应为 medium
        # now=2026-05-07, last_used=2026-01-27 -> 约 101 天
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "medium-user",
                        "access_key_id": "LTAI000000002222",
                        "status": "Active",
                        "create_date": "2025-01-01T00:00:00Z",
                        "last_used_date": "2026-01-27T00:00:00Z",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ram_stale_access_key"]
        self.assertTrue(len(matched) > 0)
        self.assertEqual("medium", matched[0].severity)

    def test_stale_access_key_high_severity(self):
        # 闲置 200 天，落在 >= 180 天区间，应为 high
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "high-user",
                        "access_key_id": "LTAI000000003333",
                        "status": "Active",
                        "create_date": "2024-01-01T00:00:00Z",
                        "last_used_date": "2024-10-01T00:00:00Z",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ram_stale_access_key"]
        self.assertTrue(len(matched) > 0)
        self.assertEqual("high", matched[0].severity)

    def test_stale_access_key_privilege_upgrade(self):
        # 闲置 45 天本来是 low，但绑定 AdministratorAccess，升级为 high
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "admin-user",
                        "access_key_id": "LTAI000000004444",
                        "status": "Active",
                        "create_date": "2025-12-01T00:00:00Z",
                        "last_used_date": "2026-03-23T00:00:00Z",
                    }
                ],
                ram_user_policies=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "admin-user",
                        "policy_name": "AdministratorAccess",
                        "policy_type": "System",
                    }
                ]
            )
        )
        matched = [item for item in findings if item.check_id == "ram_stale_access_key"]
        self.assertTrue(len(matched) > 0)
        self.assertEqual("high", matched[0].severity)

    def test_access_key_rotation(self):
        # AK 创建超过 365 天，应触发轮转巡检
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "long-lived-user",
                        "access_key_id": "LTAI000000005555",
                        "status": "Active",
                        "create_date": "2024-01-01T00:00:00Z",
                        "last_used_date": "2026-04-01T00:00:00Z",
                    }
                ]
            )
        )
        self.assertIn("ram_access_key_rotation", {item.check_id for item in findings})

    def test_access_key_recent_not_rotation(self):
        # AK 创建不到 365 天，不应触发轮转巡检
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "fresh-user",
                        "access_key_id": "LTAI000000006666",
                        "status": "Active",
                        "create_date": "2026-01-01T00:00:00Z",
                        "last_used_date": "2026-04-01T00:00:00Z",
                    }
                ]
            )
        )
        self.assertNotIn("ram_access_key_rotation", {item.check_id for item in findings})

    def test_inactive_access_key_cleanup(self):
        # Inactive AK 禁用超过 90 天，应触发清理巡检
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "disabled-user",
                        "access_key_id": "LTAI000000007777",
                        "status": "Inactive",
                        "create_date": "2024-06-01T00:00:00Z",
                        "last_used_date": "2025-06-01T00:00:00Z",
                    }
                ]
            )
        )
        self.assertIn("ram_inactive_access_key_cleanup", {item.check_id for item in findings})

    def test_inactive_access_key_recent_not_cleanup(self):
        # Inactive AK 禁用不到 90 天，不应触发清理巡检
        findings = run_with(
            make_details(
                ram_access_keys=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "recent-disabled-user",
                        "access_key_id": "LTAI000000008888",
                        "status": "Inactive",
                        "create_date": "2026-03-01T00:00:00Z",
                        "last_used_date": "2026-03-01T00:00:00Z",
                    }
                ]
            )
        )
        self.assertNotIn("ram_inactive_access_key_cleanup", {item.check_id for item in findings})

    def test_mfa_query_failed_user_not_reported_as_without_mfa(self):
        # GetUserMFAInfo 权限不足时查询失败，不应误判为"未启用 MFA"
        findings = run_with(
            make_details(
                ram_users=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "mfa-failed-user",
                        "resource_id": "mfa-failed-user",
                    }
                ],
                ram_user_mfa=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "global",
                        "user_name": "mfa-failed-user",
                        "resource_id": "mfa-failed-user",
                        "mfa_enabled": "false",
                        "mfa_query_failed": "true",
                    }
                ]
            )
        )
        self.assertNotIn("ram_user_without_mfa", {item.check_id for item in findings})

    def test_metric_idle_ecs(self):
        config = dataclasses.replace(ChecksConfig.default(), metric_checks_enabled=True)
        findings = run_with(
            make_details(
                metric_summaries=[
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "resource_id": "i-001",
                        "resource_name": "web-01",
                        "check_id": "metric_idle_ecs",
                        "metric_role": "ecs_cpu",
                        "window_days": "30",
                        "average": "30",
                        "maximum": "60",
                        "datapoints": "30",
                    },
                    {
                        "subscription": "dev",
                        "account_id": "1001",
                        "region_id": "cn-shanghai",
                        "resource_id": "i-001",
                        "resource_name": "web-01",
                        "check_id": "metric_idle_ecs",
                        "metric_role": "ecs_network_out",
                        "window_days": "30",
                        "average": "2048",
                        "maximum": "4096",
                        "datapoints": "30",
                    },
                ]
            ),
            config=config,
        )
        self.assertNotIn("metric_idle_ecs", {item.check_id for item in findings})


if __name__ == "__main__":
    unittest.main()
