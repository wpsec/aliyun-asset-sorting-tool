#!/usr/bin/env python3
"""
通过 aliyun CLI 导出阿里云资产元数据到 CSV 和 Excel 报告。

脚本刻意不接收 AK/SK 参数。请先在 aliyun CLI 中配置 profile，
运行时只传入 profile 名称，避免密钥进入脚本或命令历史。
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import json
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from checks import (  # noqa: E402
    FINDING_COLUMNS,
    FINDING_SUMMARY_COLUMNS,
    CheckContext,
    ChecksConfig,
    finding_rows,
    finding_summary_rows,
    run_checks,
    split_finding_rows,
)


CSV_COLUMNS = [
    "subscription",
    "profile",
    "source",
    "account_id",
    "region_id",
    "zone_id",
    "service_code",
    "service",
    "resource_type",
    "resource_type_name",
    "resource_id",
    "resource_name",
    "status",
    "resource_group_id",
    "create_time",
    "expire_time",
    "tags",
    "ip_addresses",
]


RAW_RESOURCE_COLUMNS = [
    ("subscription", "订阅"),
    ("profile", "Profile"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("zone_id", "可用区"),
    ("service_code", "服务码"),
    ("service", "云服务"),
    ("resource_type", "资源类型"),
    ("resource_type_name", "资产类型"),
    ("resource_id", "资源ID"),
    ("resource_name", "资源名称"),
    ("status", "状态"),
    ("resource_group_id", "资源组ID"),
    ("create_time", "创建时间"),
    ("expire_time", "到期时间"),
    ("tags", "标签"),
    ("ip_addresses", "IP地址"),
]

SUMMARY_COLUMNS = [
    ("subscription", "订阅"),
    ("service_code", "服务码"),
    ("service", "云服务"),
    ("resource_type", "资源类型"),
    ("resource_type_name", "资产类型"),
    ("count", "数量"),
]

REPORT_INFO_COLUMNS = [
    ("item", "项目"),
    ("value", "内容"),
]

COLLECTION_EVENT_COLUMNS = [
    ("subscription", "订阅"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("service", "云服务"),
    ("api", "接口"),
    ("resource_id", "资源ID"),
    ("status", "状态"),
    ("message", "说明"),
]

SERVICE_NAMES = {
    "actiontrail": "操作审计",
    "adb": "AnalyticDB",
    "alidns": "云解析DNS",
    "alb": "应用型负载均衡",
    "arms": "应用实时监控",
    "cdn": "CDN",
    "cen": "云企业网",
    "cms": "云监控",
    "config": "配置审计",
    "cr": "容器镜像服务",
    "cs": "容器服务Kubernetes版",
    "dcdn": "DCDN",
    "dds": "MongoDB",
    "ebs": "块存储",
    "eci": "弹性容器实例",
    "ecs": "云服务器",
    "eip": "弹性公网IP",
    "ga": "全球加速",
    "hbase": "HBase",
    "kms": "密钥管理服务",
    "kvstore": "Redis/Tair",
    "log": "日志服务",
    "nas": "文件存储NAS",
    "nat": "NAT网关",
    "nlb": "网络型负载均衡",
    "oss": "对象存储",
    "pam": "运维安全中心",
    "polardb": "PolarDB",
    "privatezone": "PrivateZone",
    "pvtz": "PrivateZone",
    "ram": "访问控制",
    "rds": "云数据库RDS",
    "redis": "Redis/Tair",
    "resourcecenter": "资源中心",
    "resourcemanager": "资源管理",
    "resourcesharing": "资源共享",
    "slb": "传统型负载均衡",
    "sls": "日志服务",
    "tag": "标签服务",
    "vpc": "专有网络",
    "vpn": "VPN",
    "yundun-bastionhost": "堡垒机",
    "yundun-cloudfirewall": "云防火墙",
    "yundun-sas": "云安全中心",
    "yundun-waf": "Web应用防火墙",
}

RESOURCE_TYPE_NAMES = {
    "ACS::ECS::AutoSnapshotPolicy": "自动快照策略",
    "ACS::ECS::Disk": "云盘",
    "ACS::ECS::Instance": "云服务器",
    "ACS::ECS::KeyPair": "密钥对",
    "ACS::ECS::NetworkInterface": "弹性网卡",
    "ACS::ECS::SecurityGroup": "安全组",
    "ACS::ECS::Snapshot": "快照",
    "ACS::KMS::Key": "密钥",
    "ACS::KMS::Secret": "凭据",
    "ACS::NAS::FileSystem": "NAS文件系统",
    "ACS::OSS::Bucket": "OSS Bucket",
    "ACS::RAM::User": "RAM用户",
    "ACS::RAM::Role": "RAM角色",
    "ACS::RDS::DBInstance": "RDS实例",
    "ACS::Redis::Instance": "Redis/Tair实例",
    "ACS::SLB::LoadBalancer": "传统型负载均衡",
    "ACS::SLS::Project": "SLS Project",
    "ACS::SLS::Logstore": "SLS Logstore",
    "ACS::VPC::EIP": "弹性公网IP",
    "ACS::VPC::EipAddress": "弹性公网IP",
    "ACS::VPC::NatGateway": "NAT网关",
    "ACS::VPC::RouteTable": "路由表",
    "ACS::VPC::VPC": "专有网络",
    "ACS::VPC::VSwitch": "交换机",
    "ACS::VPC::VpnGateway": "VPN网关",
    "ACS::VPC::VpnConnection": "VPN连接",
    "ACS::PVTZ::Zone": "PrivateZone",
}

ECS_INSTANCE_COLUMNS = [
    ("subscription", "订阅"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("zone_id", "可用区"),
    ("instance_id", "实例ID"),
    ("instance_name", "实例名称"),
    ("host_name", "主机名"),
    ("status", "状态"),
    ("instance_type", "实例规格"),
    ("cpu", "CPU"),
    ("memory_mb", "内存MB"),
    ("os_name", "操作系统"),
    ("image_id", "镜像ID"),
    ("vpc_id", "VPC ID"),
    ("vswitch_id", "交换机ID"),
    ("private_ip", "私网IP"),
    ("public_ip", "公网IP"),
    ("eip", "EIP"),
    ("security_group_ids", "安全组ID"),
    ("charge_type", "付费类型"),
    ("creation_time", "创建时间"),
    ("expired_time", "到期时间"),
    ("tags", "标签"),
]

ECS_DISK_COLUMNS = [
    ("subscription", "订阅"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("zone_id", "可用区"),
    ("disk_id", "磁盘ID"),
    ("disk_name", "磁盘名称"),
    ("status", "状态"),
    ("category", "磁盘类型"),
    ("disk_type", "系统/数据盘"),
    ("size_gb", "容量GB"),
    ("instance_id", "挂载实例ID"),
    ("device", "挂载设备"),
    ("encrypted", "是否加密"),
    ("portable", "是否可卸载"),
    ("creation_time", "创建时间"),
    ("expired_time", "到期时间"),
    ("tags", "标签"),
]

ECS_SECURITY_GROUP_COLUMNS = [
    ("subscription", "订阅"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("security_group_id", "安全组ID"),
    ("security_group_name", "安全组名称"),
    ("vpc_id", "VPC ID"),
    ("security_group_type", "安全组类型"),
    ("description", "描述"),
    ("creation_time", "创建时间"),
    ("tags", "标签"),
]

SAS_VULNERABILITY_COLUMNS = [
    ("subscription", "订阅"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("vul_type", "漏洞类型"),
    ("status", "状态码"),
    ("status_name", "状态"),
    ("level", "风险等级"),
    ("necessity", "修复必要性"),
    ("can_fix", "是否可修复"),
    ("vulnerability_name", "漏洞名称"),
    ("alias_name", "漏洞公告/别名"),
    ("related", "CVE/关联编号"),
    ("primary_id", "漏洞记录ID"),
    ("instance_id", "实例ID"),
    ("instance_name", "实例名称"),
    ("uuid", "资产UUID"),
    ("ip", "IP"),
    ("internet_ip", "公网IP"),
    ("intranet_ip", "私网IP"),
    ("os_name", "操作系统"),
    ("package_name", "软件包"),
    ("package_version", "当前版本"),
    ("full_version", "完整版本"),
    ("match_detail", "命中条件"),
    ("fix_command", "修复命令"),
    ("first_seen", "首次发现时间"),
    ("last_seen", "最近发现时间"),
    ("modified_at", "更新时间"),
]

SAS_VUL_TYPES = ("cve", "sys", "cms", "app", "emg", "sca")

SAS_VUL_TYPE_NAMES = {
    "cve": "Linux软件漏洞",
    "sys": "Windows系统漏洞",
    "cms": "Web-CMS漏洞",
    "app": "应用漏洞",
    "emg": "应急漏洞",
    "sca": "应用漏洞（软件成分分析）",
}

SAS_VUL_STATUS_NAMES = {
    "1": "未修复",
    "2": "修复失败",
    "3": "回滚失败",
    "4": "修复中",
    "5": "回滚中",
    "6": "验证中",
    "7": "修复成功",
    "8": "修复成功待重启",
    "9": "回滚成功",
    "10": "已忽略",
    "11": "回滚成功待重启",
    "12": "漏洞不存在",
    "20": "已失效",
}


@dataclasses.dataclass(frozen=True)
class Subscription:
    profile: str
    label: str
    multi_account_scope: str = ""


@dataclasses.dataclass(frozen=True)
class Sheet:
    name: str
    columns: list[tuple[str, str]]
    rows: list[dict[str, Any]]


@dataclasses.dataclass
class DetailedAssets:
    ecs_instances: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ecs_disks: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ecs_security_groups: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ecs_network_interfaces: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ecs_security_group_rules: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_vswitches: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_eips: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_nat_gateways: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_snat_entries: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_dnat_entries: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_vpn_gateways: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_vpn_connections: list[dict[str, str]] = dataclasses.field(default_factory=list)
    vpc_ssl_vpn_servers: list[dict[str, str]] = dataclasses.field(default_factory=list)
    slb_load_balancers: list[dict[str, str]] = dataclasses.field(default_factory=list)
    slb_listeners: list[dict[str, str]] = dataclasses.field(default_factory=list)
    alb_load_balancers: list[dict[str, str]] = dataclasses.field(default_factory=list)
    alb_listeners: list[dict[str, str]] = dataclasses.field(default_factory=list)
    alb_server_groups: list[dict[str, str]] = dataclasses.field(default_factory=list)
    alb_server_group_servers: list[dict[str, str]] = dataclasses.field(default_factory=list)
    nlb_load_balancers: list[dict[str, str]] = dataclasses.field(default_factory=list)
    nlb_listeners: list[dict[str, str]] = dataclasses.field(default_factory=list)
    nlb_server_groups: list[dict[str, str]] = dataclasses.field(default_factory=list)
    nlb_server_group_servers: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ram_users: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ram_access_keys: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ram_user_mfa: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ram_groups: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ram_group_users: list[dict[str, str]] = dataclasses.field(default_factory=list)
    oss_buckets: list[dict[str, str]] = dataclasses.field(default_factory=list)
    ecs_snapshot_policy_associations: list[dict[str, str]] = dataclasses.field(default_factory=list)
    rds_instances: list[dict[str, str]] = dataclasses.field(default_factory=list)
    rds_net_infos: list[dict[str, str]] = dataclasses.field(default_factory=list)
    rds_ip_arrays: list[dict[str, str]] = dataclasses.field(default_factory=list)
    redis_instances: list[dict[str, str]] = dataclasses.field(default_factory=list)
    redis_net_infos: list[dict[str, str]] = dataclasses.field(default_factory=list)
    metric_summaries: list[dict[str, str]] = dataclasses.field(default_factory=list)
    sas_vulnerabilities: list[dict[str, str]] = dataclasses.field(default_factory=list)
    collection_events: list[dict[str, str]] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class TopologyBuckets:
    subscription: str
    groups: dict[str, dict[str, Any]]
    unassigned: dict[str, Any]


VERIFY_CHECKS = [
    {
        "name": "resourcecenter SearchResources",
        "expect": "allow",
        "args": ["resourcecenter", "SearchResources", "--MaxResults", "1"],
    },
    {
        "name": "ecs DescribeRegions",
        "expect": "allow",
        "args": ["ecs", "DescribeRegions"],
    },
    {
        "name": "vpc DescribeRegions",
        "expect": "allow",
        "args": ["vpc", "DescribeRegions"],
    },
    {
        "name": "vpc DescribeSslVpnServers",
        "expect": "allow",
        "args": [
            "vpc",
            "DescribeSslVpnServers",
            "--RegionId",
            "cn-shanghai",
            "--PageSize",
            "1",
        ],
    },
    {
        "name": "rds DescribeRegions",
        "expect": "allow",
        "args": ["rds", "DescribeRegions"],
    },
    {
        "name": "kms GetSecretValue",
        "expect": "deny",
        "args": [
            "kms",
            "GetSecretValue",
            "--SecretName",
            "asset-inventory-permission-check-not-exist",
            "--DryRun",
            "true",
        ],
    },
    {
        "name": "ecs DescribeInvocationResults",
        "expect": "deny",
        "args": [
            "ecs",
            "DescribeInvocationResults",
            "--RegionId",
            "cn-shanghai",
            "--MaxResults",
            "1",
        ],
    },
    {
        "name": "cs DescribeClusterUserKubeconfig",
        "expect": "deny",
        "args": [
            "cs",
            "DescribeClusterUserKubeconfig",
            "--ClusterId",
            "asset-inventory-permission-check-not-exist",
        ],
    },
]

TOPOLOGY_RELEVANT_APIS = {
    "DescribeVSwitches",
    "DescribeNetworkInterfaces",
    "DescribeEipAddresses",
    "DescribeNatGateways",
    "DescribeVpnGateways",
    "DescribeVpnConnections",
    "DescribeSslVpnServers",
    "DescribeLoadBalancers",
    "ListLoadBalancers",
    "DescribeLoadBalancerListeners",
    "ListListeners",
    "ListServerGroups",
    "ListServerGroupServers",
    "DescribeDBInstances",
    "DescribeInstances",
    "DescribeDBInstanceNetInfo",
}


class AliyunCliError(RuntimeError):
    def __init__(self, message: str, returncode: int, stdout: str, stderr: str):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def sanitize_aliyun_error_text(text: str) -> str:
    sanitized = text or ""
    sensitive_patterns = (
        r"(?i)(AccessKeyId=)[^&\s\"']+",
        r"(?i)(Signature=)[^&\s\"']+",
        r"(?i)(SecurityToken=)[^&\s\"']+",
        r"(?i)(SignatureNonce=)[^&\s\"']+",
        r"(?i)(Authorization:\s*)[^\s\"']+",
    )
    for pattern in sensitive_patterns:
        sanitized = re.sub(pattern, r"\1<redacted>", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def compact_aliyun_error_text(text: str) -> str:
    sanitized = sanitize_aliyun_error_text(text)
    if not sanitized:
        return ""

    error_code = regex_group(r"ErrorCode:\s*([^\s]+)", sanitized)
    request_id = regex_group(r"RequestId:\s*([^\s]+)", sanitized)
    message = regex_group(
        r"Message:\s*(.*?)(?:\s+RespHeaders:|\s+AccessDeniedDetail:|$)",
        sanitized,
    )
    parts = []
    if error_code:
        parts.append(f"ErrorCode={error_code}")
    if message:
        parts.append(f"Message={message}")
    if request_id:
        parts.append(f"RequestId={request_id}")
    if parts:
        return "; ".join(parts)[:500]
    return sanitized[:500]


def regex_group(pattern: str, text: str) -> str:
    matched = re.search(pattern, text)
    if not matched:
        return ""
    return matched.group(1).strip()


def aliyun_error_detail(stdout: str, stderr: str) -> str:
    for text in (stderr, stdout):
        compact = compact_aliyun_error_text(text)
        if compact:
            return compact
    return "无错误详情"


def build_base_cmd(profile: str | None, region: str | None) -> list[str]:
    cmd = ["aliyun"]
    if profile:
        cmd.extend(["--profile", profile])
    if region:
        cmd.extend(["--region", region])
    return cmd


def run_aliyun(
    args: list[str],
    *,
    profile: str | None,
    region: str | None,
    timeout: int,
) -> dict[str, Any]:
    cmd = build_base_cmd(profile, region) + args
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )

    if proc.returncode != 0:
        raise AliyunCliError(
            (
                f"aliyun 命令执行失败: {' '.join(args[:2])}; "
                f"{aliyun_error_detail(proc.stdout, proc.stderr)}"
            ),
            proc.returncode,
            proc.stdout,
            proc.stderr,
        )

    stdout = proc.stdout.strip()
    if not stdout:
        return {}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AliyunCliError(
            f"aliyun 输出不是 JSON: {' '.join(args[:2])}",
            proc.returncode,
            proc.stdout,
            proc.stderr,
        ) from exc

    if not isinstance(data, dict):
        return {"Result": data}
    return data


def extract_resources(data: dict[str, Any]) -> list[dict[str, Any]]:
    resources = data.get("Resources")
    if isinstance(resources, list):
        return [item for item in resources if isinstance(item, dict)]
    if isinstance(resources, dict):
        for key in ("Resource", "Resources", "Items", "Item"):
            value = resources.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    for key in ("ResourceList", "Items", "Data"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    return []


def pick(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return ""


def compact_json(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return value


def format_unix_millis(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        timestamp = float(value) / 1000
    except (TypeError, ValueError):
        return str(value)
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def pick_path(item: dict[str, Any], *path: str) -> Any:
    current: Any = item
    for key in path:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
        if current in (None, ""):
            return ""
    return current


def as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in (
            "IpAddress",
            "SecurityGroupId",
            "Tag",
            "Disk",
            "Instance",
            "SecurityGroup",
        ):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
            if nested not in (None, ""):
                return [nested]
        return [value]
    return [value]


def join_values(value: Any) -> str:
    values = []
    for item in as_list(value):
        if item in (None, ""):
            continue
        if isinstance(item, dict):
            values.append(compact_json(item))
        else:
            values.append(str(item))
    return ";".join(values)


def normalize_tags(value: Any) -> str:
    if not value:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        return ";".join(f"{key}={val}" for key, val in sorted(value.items()))

    if isinstance(value, list):
        pairs: list[str] = []
        for item in value:
            if isinstance(item, dict):
                key = pick(item, "Key", "TagKey", "key", "tagKey")
                val = pick(item, "Value", "TagValue", "value", "tagValue")
                if key:
                    pairs.append(f"{key}={val}")
            elif item:
                pairs.append(str(item))
        return ";".join(pairs)

    return compact_json(value)


def service_from_resource_type(resource_type: str) -> str:
    parts = resource_type.split("::")
    if len(parts) >= 2 and parts[0] == "ACS":
        return parts[1].lower()
    return ""


def display_with_name(code: str, names: dict[str, str]) -> str:
    code = code or ""
    name = names.get(code)
    if not code:
        return ""
    if not name:
        return code
    return f"{code}（{name}）"


def resource_type_display(resource_type: str) -> str:
    if not resource_type:
        return ""
    return RESOURCE_TYPE_NAMES.get(resource_type, "")


def normalize_resource(
    item: dict[str, Any],
    source: str,
    subscription: Subscription,
) -> dict[str, str]:
    resource_type = str(pick(item, "ResourceType", "resourceType", "Type", "type"))
    service_code = str(pick(item, "Service", "ProductCode", "ProductName", "service"))
    if not service_code:
        service_code = service_from_resource_type(resource_type)

    row = {
        "subscription": subscription.label,
        "profile": subscription.profile,
        "source": source,
        "account_id": pick(item, "AccountId", "accountId", "OwnerId"),
        "region_id": pick(item, "RegionId", "ResourceRegionId", "regionId"),
        "zone_id": pick(item, "ZoneId", "zoneId"),
        "service_code": service_code,
        "service": display_with_name(service_code, SERVICE_NAMES),
        "resource_type": resource_type,
        "resource_type_name": resource_type_display(resource_type),
        "resource_id": pick(item, "ResourceId", "resourceId", "Id", "id"),
        "resource_name": pick(
            item,
            "ResourceName",
            "resourceName",
            "Name",
            "name",
            "InstanceName",
        ),
        "status": pick(item, "Status", "ResourceStatus", "status"),
        "resource_group_id": pick(item, "ResourceGroupId", "resourceGroupId"),
        "create_time": pick(item, "CreateTime", "CreateDate", "CreationTime"),
        "expire_time": pick(item, "ExpireTime", "ExpiredTime", "ExpirationTime"),
        "tags": normalize_tags(pick(item, "Tags", "Tag", "tags")),
        "ip_addresses": compact_json(pick(item, "IpAddresses", "IpAddress", "IPs")),
    }

    return {key: str(value) for key, value in row.items()}


def extract_nested_list(data: dict[str, Any], *paths: tuple[str, ...]) -> list[dict[str, Any]]:
    for path in paths:
        current: Any = data
        for key in path:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(key)
        if isinstance(current, list):
            return [item for item in current if isinstance(item, dict)]
    return []


def regions_from_rows(rows: list[dict[str, str]], service: str) -> list[str]:
    regions = {
        row["region_id"]
        for row in rows
        if row.get("service_code") == service and row.get("region_id")
    }
    return sorted(regions)


def paged_ecs_api(
    args: argparse.Namespace,
    subscription: Subscription,
    api_name: str,
    region_id: str,
    list_paths: list[tuple[str, ...]],
) -> list[dict[str, Any]]:
    page_number = 1
    all_items: list[dict[str, Any]] = []

    while True:
        data = run_aliyun(
            [
                "ecs",
                api_name,
                "--RegionId",
                region_id,
                "--PageSize",
                "100",
                "--PageNumber",
                str(page_number),
            ],
            profile=subscription.profile,
            region=args.region or region_id,
            timeout=args.timeout,
        )
        items = extract_nested_list(data, *list_paths)
        all_items.extend(items)

        total_count = int(data.get("TotalCount") or len(all_items))
        page_size = int(data.get("PageSize") or 100)
        if page_number * page_size >= total_count or not items:
            return all_items
        page_number += 1


def paged_rpc_api(
    args: argparse.Namespace,
    subscription: Subscription,
    service: str,
    api_name: str,
    region_id: str,
    list_paths: list[tuple[str, ...]],
    *,
    extra_args: list[str] | None = None,
    page_size: int = 100,
) -> list[dict[str, Any]]:
    page_number = 1
    all_items: list[dict[str, Any]] = []

    while True:
        cli_args = [service, api_name]
        if region_id:
            cli_args.extend(["--RegionId", region_id])
        cli_args.extend(["--PageSize", str(page_size), "--PageNumber", str(page_number)])
        if extra_args:
            cli_args.extend(extra_args)

        data = run_aliyun(
            cli_args,
            profile=subscription.profile,
            region=args.region or region_id,
            timeout=args.timeout,
        )
        items = extract_nested_list(data, *list_paths)
        all_items.extend(items)

        total_count = int(data.get("TotalCount") or data.get("Total") or len(all_items))
        returned_page_size = int(data.get("PageSize") or data.get("PageRecordCount") or page_size)
        if page_number * returned_page_size >= total_count or not items:
            return all_items
        page_number += 1


def marker_rpc_api(
    args: argparse.Namespace,
    subscription: Subscription,
    service: str,
    api_name: str,
    list_paths: list[tuple[str, ...]],
    *,
    extra_args: list[str] | None = None,
    max_items: int = 1000,
) -> list[dict[str, Any]]:
    marker = ""
    all_items: list[dict[str, Any]] = []

    while True:
        cli_args = [service, api_name, "--MaxItems", str(max_items)]
        if marker:
            cli_args.extend(["--Marker", marker])
        if extra_args:
            cli_args.extend(extra_args)

        data = run_aliyun(
            cli_args,
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )
        items = extract_nested_list(data, *list_paths)
        all_items.extend(items)

        truncated = str(data.get("IsTruncated", "")).lower() == "true"
        marker = str(data.get("Marker") or "")
        if not truncated or not marker:
            return all_items


def next_token_rpc_api(
    args: argparse.Namespace,
    subscription: Subscription,
    service: str,
    api_name: str,
    region_id: str,
    list_paths: list[tuple[str, ...]],
    *,
    extra_args: list[str] | None = None,
    max_results: int = 100,
    include_region_id: bool = True,
) -> list[dict[str, Any]]:
    next_token = ""
    all_items: list[dict[str, Any]] = []

    while True:
        cli_args = [service, api_name]
        endpoint_region = args.region or region_id
        if include_region_id and region_id:
            cli_args.extend(["--RegionId", region_id])
        elif region_id:
            endpoint_region = region_id
        cli_args.extend(["--MaxResults", str(max_results)])
        if next_token:
            cli_args.extend(["--NextToken", next_token])
        if extra_args:
            cli_args.extend(extra_args)

        data = run_aliyun(
            cli_args,
            profile=subscription.profile,
            region=endpoint_region,
            timeout=args.timeout,
        )
        items = extract_nested_list(data, *list_paths)
        all_items.extend(items)

        next_token = str(data.get("NextToken") or "")
        if not next_token or not items:
            return all_items


def normalize_ecs_instance(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    vpc_attributes = item.get("VpcAttributes") if isinstance(item.get("VpcAttributes"), dict) else {}
    eip_address = item.get("EipAddress") if isinstance(item.get("EipAddress"), dict) else {}

    private_ip = join_values(
        pick_path(vpc_attributes, "PrivateIpAddress", "IpAddress")
        or pick_path(item, "InnerIpAddress", "IpAddress")
    )
    public_ip = join_values(pick_path(item, "PublicIpAddress", "IpAddress"))
    security_group_ids = join_values(pick_path(item, "SecurityGroupIds", "SecurityGroupId"))

    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "zone_id": pick(item, "ZoneId"),
        "instance_id": pick(item, "InstanceId"),
        "instance_name": pick(item, "InstanceName"),
        "host_name": pick(item, "HostName"),
        "status": pick(item, "Status"),
        "instance_type": pick(item, "InstanceType"),
        "cpu": pick(item, "Cpu"),
        "memory_mb": pick(item, "Memory"),
        "os_name": pick(item, "OSName", "OSNameEn"),
        "image_id": pick(item, "ImageId"),
        "vpc_id": pick(vpc_attributes, "VpcId"),
        "vswitch_id": pick(vpc_attributes, "VSwitchId"),
        "private_ip": private_ip,
        "public_ip": public_ip,
        "eip": pick(eip_address, "IpAddress"),
        "security_group_ids": security_group_ids,
        "charge_type": pick(item, "InstanceChargeType"),
        "creation_time": pick(item, "CreationTime"),
        "expired_time": pick(item, "ExpiredTime"),
        "tags": normalize_tags(pick_path(item, "Tags", "Tag")),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ecs_disk(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "zone_id": pick(item, "ZoneId"),
        "disk_id": pick(item, "DiskId"),
        "disk_name": pick(item, "DiskName"),
        "status": pick(item, "Status"),
        "category": pick(item, "Category"),
        "disk_type": pick(item, "Type"),
        "size_gb": pick(item, "Size"),
        "instance_id": pick(item, "InstanceId"),
        "device": pick(item, "Device"),
        "encrypted": pick(item, "Encrypted"),
        "portable": pick(item, "Portable"),
        "creation_time": pick(item, "CreationTime"),
        "expired_time": pick(item, "ExpiredTime"),
        "tags": normalize_tags(pick_path(item, "Tags", "Tag")),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ecs_security_group(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "security_group_id": pick(item, "SecurityGroupId"),
        "security_group_name": pick(item, "SecurityGroupName"),
        "vpc_id": pick(item, "VpcId"),
        "security_group_type": pick(item, "SecurityGroupType"),
        "description": pick(item, "Description"),
        "creation_time": pick(item, "CreationTime"),
        "tags": normalize_tags(pick_path(item, "Tags", "Tag")),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ecs_network_interface(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "zone_id": pick(item, "ZoneId"),
        "network_interface_id": pick(item, "NetworkInterfaceId"),
        "resource_id": pick(item, "NetworkInterfaceId"),
        "name": pick(item, "NetworkInterfaceName"),
        "status": pick(item, "Status"),
        "type": pick(item, "Type"),
        "vpc_id": pick(item, "VpcId"),
        "vswitch_id": pick(item, "VSwitchId"),
        "private_ip": pick(item, "PrivateIpAddress"),
        "instance_id": pick(item, "InstanceId"),
        "security_group_ids": join_values(pick_path(item, "SecurityGroupIds", "SecurityGroupId")),
        "creation_time": pick(item, "CreationTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ecs_security_group_rule(
    item: dict[str, Any],
    group: dict[str, str],
) -> dict[str, str]:
    row = {
        "subscription": group.get("subscription", ""),
        "account_id": group.get("account_id", ""),
        "region_id": group.get("region_id", ""),
        "security_group_id": group.get("security_group_id", ""),
        "resource_id": group.get("security_group_id", ""),
        "resource_name": group.get("security_group_name", ""),
        "ip_protocol": pick(item, "IpProtocol"),
        "port_range": pick(item, "PortRange"),
        "source_cidr_ip": pick(item, "SourceCidrIp"),
        "ipv6_source_cidr_ip": pick(item, "Ipv6SourceCidrIp"),
        "policy": pick(item, "Policy"),
        "direction": pick(item, "Direction"),
        "priority": pick(item, "Priority"),
        "description": pick(item, "Description"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_vswitch(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "zone_id": pick(item, "ZoneId"),
        "vswitch_id": pick(item, "VSwitchId"),
        "resource_id": pick(item, "VSwitchId"),
        "resource_name": pick(item, "VSwitchName", "Name", "VSwitchId"),
        "status": pick(item, "Status"),
        "vpc_id": pick(item, "VpcId"),
        "cidr_block": pick(item, "CidrBlock"),
        "available_ip_address_count": pick(item, "AvailableIpAddressCount"),
        "creation_time": pick(item, "CreationTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_vpc_eip(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "allocation_id": pick(item, "AllocationId"),
        "resource_id": pick(item, "AllocationId"),
        "resource_name": pick(item, "Name"),
        "ip_address": pick(item, "IpAddress"),
        "status": pick(item, "Status"),
        "instance_id": pick(item, "InstanceId"),
        "associated_instance_id": pick(item, "AssociatedInstanceId"),
        "bind_resource_id": pick(item, "BindResourceId"),
        "instance_type": pick(item, "InstanceType"),
        "bandwidth": pick(item, "Bandwidth"),
        "charge_type": pick(item, "InternetChargeType", "InstanceChargeType"),
        "creation_time": pick(item, "AllocationTime", "CreationTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_nat_gateway(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "nat_gateway_id": pick(item, "NatGatewayId"),
        "resource_id": pick(item, "NatGatewayId"),
        "resource_name": pick(item, "Name", "NatGatewayName"),
        "status": pick(item, "Status"),
        "vpc_id": pick(item, "VpcId"),
        "spec": pick(item, "Spec"),
        "snat_table_ids": join_values(pick_path(item, "SnatTableIds", "SnatTableId")),
        "forward_table_ids": join_values(pick_path(item, "ForwardTableIds", "ForwardTableId")),
        "creation_time": pick(item, "CreationTime", "CreatedTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_nat_rule(
    item: dict[str, Any],
    nat_gateway_id: str,
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": region_id,
        "nat_gateway_id": nat_gateway_id,
        "resource_id": pick(item, "SnatEntryId", "ForwardEntryId"),
        "status": pick(item, "Status"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_vpn_gateway(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "vpn_gateway_id": pick(item, "VpnGatewayId"),
        "resource_id": pick(item, "VpnGatewayId"),
        "resource_name": pick(item, "Name"),
        "status": pick(item, "Status"),
        "vpc_id": pick(item, "VpcId"),
        "create_time": pick(item, "CreateTime", "CreationTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_vpn_connection(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "vpn_connection_id": pick(item, "VpnConnectionId"),
        "resource_id": pick(item, "VpnConnectionId"),
        "resource_name": pick(item, "Name"),
        "status": pick(item, "Status"),
        "vpn_gateway_id": pick(item, "VpnGatewayId"),
        "create_time": pick(item, "CreateTime", "CreationTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ssl_vpn_server(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "ssl_vpn_server_id": pick(item, "SslVpnServerId"),
        "resource_id": pick(item, "SslVpnServerId"),
        "resource_name": pick(item, "Name"),
        "vpn_gateway_id": pick(item, "VpnGatewayId"),
        "internet_ip": pick(item, "InternetIp"),
        "connections": pick(item, "Connections"),
        "max_connections": pick(item, "MaxConnections"),
        "local_subnet": pick(item, "LocalSubnet"),
        "client_ip_pool": pick(item, "ClientIpPool"),
        "create_time": pick(item, "CreateTime", "CreationTime"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_load_balancer(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "load_balancer_id": pick(item, "LoadBalancerId"),
        "resource_id": pick(item, "LoadBalancerId"),
        "load_balancer_name": pick(item, "LoadBalancerName", "Name"),
        "resource_name": pick(item, "LoadBalancerName", "Name"),
        "status": pick(item, "LoadBalancerStatus", "Status"),
        "address": pick(item, "Address", "DnsName"),
        "address_type": pick(item, "AddressType"),
        "vpc_id": pick(item, "VpcId"),
        "creation_time": pick(item, "CreateTime", "CreationTime"),
        "tags": normalize_tags(pick_path(item, "Tags", "Tag")),
        "resource_group_id": pick(item, "ResourceGroupId"),
    }
    return {key: str(value) for key, value in row.items()}


def extract_explicit_server_group_ids(item: dict[str, Any]) -> str:
    ids: list[str] = []

    def append_from_value(value: Any) -> None:
        for entry in as_list(value):
            if isinstance(entry, dict):
                server_group_id = str(pick(entry, "ServerGroupId"))
                if server_group_id:
                    ids.append(server_group_id)
            elif entry not in (None, ""):
                ids.append(str(entry))

    append_from_value(pick(item, "DefaultServerGroupId", "ServerGroupId", "ServerGroupIds"))
    append_from_value(pick_path(item, "ForwardGroupConfig", "ServerGroupTuples"))
    append_from_value(pick_path(item, "ServerGroupTuples", "ServerGroupTuple"))
    append_from_value(pick_path(item, "DefaultActions", "ForwardGroupConfig", "ServerGroupTuples"))

    for action in as_list(item.get("DefaultActions")):
        if not isinstance(action, dict):
            continue
        append_from_value(pick(action, "ServerGroupId"))
        append_from_value(pick_path(action, "ForwardGroupConfig", "ServerGroupTuples"))

    deduped: list[str] = []
    seen: set[str] = set()
    for server_group_id in ids:
        if not server_group_id or server_group_id in seen:
            continue
        seen.add(server_group_id)
        deduped.append(server_group_id)
    return ";".join(deduped)


def normalize_listener(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
    load_balancer_id: str = "",
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "listener_id": pick(item, "ListenerId"),
        "resource_id": pick(item, "ListenerId") or load_balancer_id,
        "load_balancer_id": pick(item, "LoadBalancerId") or load_balancer_id,
        "protocol": pick(item, "ListenerProtocol", "Protocol"),
        "port": pick(item, "ListenerPort", "Port"),
        "status": pick(item, "ListenerStatus", "Status"),
        "server_group_ids": extract_explicit_server_group_ids(item),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_server_group(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "server_group_id": pick(item, "ServerGroupId"),
        "resource_id": pick(item, "ServerGroupId"),
        "server_group_name": pick(item, "ServerGroupName", "Name"),
        "resource_name": pick(item, "ServerGroupName", "Name"),
        "server_group_type": pick(item, "ServerGroupType"),
        "protocol": pick(item, "Protocol"),
        "vpc_id": pick(item, "VpcId"),
        "load_balancer_id": pick(item, "LoadBalancerId"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_server_group_server(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
    server_group_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": region_id,
        "server_group_id": pick(item, "ServerGroupId") or server_group_id,
        "server_id": pick(item, "ServerId"),
        "resource_id": pick(item, "ServerId"),
        "status": pick(item, "Status"),
        "port": pick(item, "Port"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ram_user(item: dict[str, Any], subscription: Subscription, account_id: str) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": "global",
        "user_name": pick(item, "UserName"),
        "resource_id": pick(item, "UserName"),
        "resource_name": pick(item, "DisplayName", "UserName"),
        "create_date": pick(item, "CreateDate"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ram_access_key(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    user_name: str,
    last_used: dict[str, Any] | None,
) -> dict[str, str]:
    last_used = last_used or {}
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": pick(last_used, "Region") or "global",
        "user_name": user_name,
        "resource_id": user_name,
        "resource_name": user_name,
        "access_key_id": pick(item, "AccessKeyId"),
        "status": pick(item, "Status"),
        "create_date": pick(item, "CreateDate"),
        "last_used_date": pick(last_used, "LastUsedDate"),
        "last_used_service": pick(last_used, "ServiceName"),
        "last_used_query_failed": pick(last_used, "QueryFailed"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ram_mfa(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    user_name: str,
) -> dict[str, str]:
    mfa_device = item.get("MFADevice") if isinstance(item.get("MFADevice"), dict) else {}
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": "global",
        "user_name": user_name,
        "resource_id": user_name,
        "mfa_enabled": "true" if pick(mfa_device, "SerialNumber") else "false",
        "serial_number": pick(mfa_device, "SerialNumber"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ram_group(item: dict[str, Any], subscription: Subscription, account_id: str) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": "global",
        "group_name": pick(item, "GroupName"),
        "resource_id": pick(item, "GroupName"),
        "resource_name": pick(item, "Comments", "GroupName"),
        "create_date": pick(item, "CreateDate"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_ram_group_user(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    group_name: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": "global",
        "group_name": group_name,
        "user_name": pick(item, "UserName"),
        "resource_id": pick(item, "UserName"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_oss_bucket(
    row: dict[str, str],
    metadata: dict[str, str] | None = None,
) -> dict[str, str]:
    metadata = metadata or {}
    bucket = {
        "subscription": row.get("subscription", ""),
        "account_id": row.get("account_id", ""),
        "region_id": row.get("region_id", ""),
        "bucket_name": row.get("resource_name") or row.get("resource_id", ""),
        "resource_id": row.get("resource_id", ""),
        "resource_name": row.get("resource_name", ""),
        "acl": metadata.get("acl", ""),
        "encryption_algorithm": metadata.get("encryption_algorithm", ""),
        "policy_public": metadata.get("policy_public", ""),
        "public_access_block": metadata.get("public_access_block", ""),
        "lifecycle_configured": metadata.get("lifecycle_configured", ""),
        "lifecycle_query_failed": metadata.get("lifecycle_query_failed", ""),
        "tags": row.get("tags", ""),
        "resource_group_id": row.get("resource_group_id", ""),
    }
    return {key: str(value) for key, value in bucket.items()}


def normalize_snapshot_policy_association(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": region_id,
        "disk_id": pick(item, "DiskId"),
        "resource_id": pick(item, "DiskId"),
        "auto_snapshot_policy_id": pick(item, "AutoSnapshotPolicyId"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_rds_instance(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "instance_id": pick(item, "DBInstanceId"),
        "resource_id": pick(item, "DBInstanceId"),
        "resource_name": pick(item, "DBInstanceDescription", "DBInstanceId"),
        "status": pick(item, "DBInstanceStatus"),
        "engine": pick(item, "Engine"),
        "engine_version": pick(item, "EngineVersion"),
        "connection_mode": pick(item, "ConnectionMode"),
        "charge_type": pick(item, "PayType", "DBInstanceNetType"),
        "vpc_id": pick(item, "VpcId", "VPCId", "VpcInstanceId"),
        "vswitch_id": pick(item, "VSwitchId", "VswitchId"),
        "tags": normalize_tags(pick_path(item, "Tags", "Tag")),
        "resource_group_id": pick(item, "ResourceGroupId"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_redis_instance(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId") or region_id,
        "instance_id": pick(item, "InstanceId"),
        "resource_id": pick(item, "InstanceId"),
        "resource_name": pick(item, "InstanceName", "InstanceId"),
        "status": pick(item, "InstanceStatus", "Status"),
        "engine": pick(item, "Engine"),
        "engine_version": pick(item, "EngineVersion"),
        "charge_type": pick(item, "ChargeType"),
        "vpc_id": pick(item, "VpcId", "VPCId", "VpcInstanceId"),
        "vswitch_id": pick(item, "VSwitchId", "VswitchId"),
        "tags": normalize_tags(pick_path(item, "Tags", "Tag")),
        "resource_group_id": pick(item, "ResourceGroupId"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_db_net_info(
    item: dict[str, Any],
    base: dict[str, str],
    service: str,
) -> dict[str, str]:
    row = {
        "subscription": base.get("subscription", ""),
        "account_id": base.get("account_id", ""),
        "region_id": base.get("region_id", ""),
        "service_code": service,
        "instance_id": base.get("instance_id", ""),
        "resource_id": base.get("instance_id", ""),
        "resource_name": base.get("resource_name", ""),
        "net_type": pick(item, "IPType", "NetType", "ConnectionStringType", "DBInstanceNetType"),
        "ip_type": pick(item, "IPAddressType", "IPType"),
        "address_type": pick(item, "AddressType"),
        "connection_string": pick(item, "ConnectionString", "ConnectionStringPrefix"),
        "port": pick(item, "Port"),
        "vpc_id": pick(item, "VpcId", "VPCId", "VpcInstanceId") or base.get("vpc_id", ""),
        "vswitch_id": pick(item, "VSwitchId", "VswitchId") or base.get("vswitch_id", ""),
        "tags": base.get("tags", ""),
        "resource_group_id": base.get("resource_group_id", ""),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_rds_ip_array(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    region_id: str,
    instance: dict[str, str],
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id or instance.get("account_id", ""),
        "region_id": pick(item, "RegionId") or region_id or instance.get("region_id", ""),
        "instance_id": instance.get("instance_id", ""),
        "resource_id": instance.get("instance_id", ""),
        "resource_name": instance.get("resource_name", ""),
        "whitelist_name": pick(item, "DBInstanceIPArrayName", "WhitelistName", "Name"),
        "whitelist_attribute": pick(item, "DBInstanceIPArrayAttribute", "WhitelistAttribute"),
        "security_ip_list": pick(item, "SecurityIPList", "SecurityIps"),
        "security_ip_type": pick(item, "SecurityIPType", "SecurityIpType"),
    }
    return {key: str(value) for key, value in row.items()}


def normalize_metric_summary(
    *,
    subscription: Subscription,
    account_id: str,
    region_id: str,
    service: str,
    resource_type: str,
    resource_id: str,
    resource_name: str,
    check_id: str,
    metric_role: str,
    namespace: str,
    metric_name: str,
    window_days: int,
    average: float,
    maximum: float,
    datapoints: int,
    query_failed: bool = False,
) -> dict[str, str]:
    row = {
        "subscription": subscription.label,
        "account_id": account_id,
        "region_id": region_id,
        "service_code": service,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "check_id": check_id,
        "metric_role": metric_role,
        "namespace": namespace,
        "metric_name": metric_name,
        "window_days": str(window_days),
        "average": f"{average:.4f}",
        "maximum": f"{maximum:.4f}",
        "datapoints": str(datapoints),
        "query_failed": "true" if query_failed else "false",
    }
    return row


def normalize_sas_vulnerability_rows(
    item: dict[str, Any],
    subscription: Subscription,
    account_id: str,
    vul_type: str,
) -> list[dict[str, str]]:
    extend_content = parse_json_value(item.get("ExtendContentJson"))
    if not isinstance(extend_content, dict):
        extend_content = {}
    packages = as_list(extend_content.get("RpmEntityList"))
    if not packages:
        packages = [{}]

    status = str(pick(item, "Status"))
    base = {
        "subscription": subscription.label,
        "account_id": pick(item, "AccountId", "OwnerId") or account_id,
        "region_id": pick(item, "RegionId"),
        "vul_type": SAS_VUL_TYPE_NAMES.get(vul_type, vul_type),
        "status": status,
        "status_name": SAS_VUL_STATUS_NAMES.get(status, ""),
        "level": pick(item, "Level"),
        "necessity": pick(item, "Necessity"),
        "can_fix": pick(item, "CanFix"),
        "vulnerability_name": pick(item, "Name"),
        "alias_name": pick(item, "AliasName"),
        "related": pick(item, "Related") or join_values(extend_content.get("cveList")),
        "primary_id": pick(item, "PrimaryId"),
        "instance_id": pick(item, "InstanceId"),
        "instance_name": pick(item, "InstanceName"),
        "uuid": pick(item, "Uuid"),
        "ip": pick(item, "Ip"),
        "internet_ip": pick(item, "InternetIp"),
        "intranet_ip": pick(item, "IntranetIp"),
        "os_name": pick(item, "OsName") or " ".join(
            part for part in (str(extend_content.get("Os") or ""), str(extend_content.get("OsRelease") or "")) if part
        ),
        "first_seen": format_unix_millis(pick(item, "FirstTs")),
        "last_seen": format_unix_millis(pick(item, "LastTs")),
        "modified_at": format_unix_millis(pick(item, "ModifyTs")),
    }

    rows = []
    for package in packages:
        package_data = package if isinstance(package, dict) else {}
        row = {
            **base,
            "package_name": pick(package_data, "Name"),
            "package_version": pick(package_data, "Version"),
            "full_version": pick(package_data, "FullVersion"),
            "match_detail": pick(package_data, "MatchDetail") or join_values(package_data.get("MatchList")),
            "fix_command": pick(package_data, "UpdateCmd"),
        }
        rows.append({key: str(value) for key, value in row.items()})
    return rows


def extend_detail_lists(target: DetailedAssets, source: DetailedAssets) -> None:
    for field in dataclasses.fields(DetailedAssets):
        getattr(target, field.name).extend(getattr(source, field.name))


def record_collection_event(
    details: DetailedAssets,
    subscription: Subscription,
    *,
    account_id: str,
    region_id: str,
    service: str,
    api: str,
    status: str,
    message: str,
    resource_id: str = "",
) -> None:
    details.collection_events.append(
        {
            "subscription": subscription.label,
            "account_id": account_id,
            "region_id": region_id,
            "service": display_with_name(service, SERVICE_NAMES),
            "api": api,
            "resource_id": resource_id,
            "status": status,
            "message": message,
        }
    )


def collect_detailed_assets(
    args: argparse.Namespace,
    subscription: Subscription,
    raw_rows: list[dict[str, str]],
    checks_config: ChecksConfig | None = None,
) -> DetailedAssets:
    if args.no_detail:
        return DetailedAssets()

    account_id = next((row["account_id"] for row in raw_rows if row.get("account_id")), "")
    ecs_regions = regions_from_rows(raw_rows, "ecs")
    vpc_regions = sorted(
        set(regions_from_rows(raw_rows, "vpc"))
        | {row.get("region_id", "") for row in raw_rows if row.get("resource_type", "").startswith("ACS::VPC::")}
    )
    slb_regions = regions_from_rows(raw_rows, "slb")
    alb_regions = regions_from_rows(raw_rows, "alb")
    nlb_regions = regions_from_rows(raw_rows, "nlb")
    details = DetailedAssets()
    print(
        f"[资产梳理] 开始详情补采 订阅={subscription.label} "
        f"ECS地域={len(ecs_regions)} VPC地域={len(vpc_regions)} "
        f"SLB地域={len(slb_regions)} ALB地域={len(alb_regions)} NLB地域={len(nlb_regions)}",
        file=sys.stderr,
    )
    should_collect_snapshot_policies = (
        checks_config is not None
        and checks_config.is_enabled("ecs_disk_without_snapshot_policy")
    )

    for region_id in ecs_regions:
        print(
            f"[资产梳理] ECS详情补采中 订阅={subscription.label} 地域={region_id}",
            file=sys.stderr,
        )
        try:
            instances = paged_ecs_api(
                args,
                subscription,
                "DescribeInstances",
                region_id,
                [("Instances", "Instance")],
            )
            details.ecs_instances.extend(
                normalize_ecs_instance(item, subscription, account_id, region_id)
                for item in instances
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] ECS云服务器详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="ecs",
                api="DescribeInstances",
                status="query_failed",
                message=str(exc),
            )

        try:
            disks = paged_ecs_api(
                args,
                subscription,
                "DescribeDisks",
                region_id,
                [("Disks", "Disk")],
            )
            region_disks = [
                normalize_ecs_disk(item, subscription, account_id, region_id)
                for item in disks
            ]
            details.ecs_disks.extend(region_disks)
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            region_disks = []
            print(
                f"[资产梳理] ECS磁盘详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )

        try:
            security_groups = paged_ecs_api(
                args,
                subscription,
                "DescribeSecurityGroups",
                region_id,
                [("SecurityGroups", "SecurityGroup")],
            )
            region_security_groups = [
                normalize_ecs_security_group(item, subscription, account_id, region_id)
                for item in security_groups
            ]
            details.ecs_security_groups.extend(region_security_groups)
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] ECS安全组详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )

        try:
            network_interfaces = paged_ecs_api(
                args,
                subscription,
                "DescribeNetworkInterfaces",
                region_id,
                [("NetworkInterfaceSets", "NetworkInterfaceSet")],
            )
            details.ecs_network_interfaces.extend(
                normalize_ecs_network_interface(item, subscription, account_id, region_id)
                for item in network_interfaces
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] ECS弹性网卡详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="ecs",
                api="DescribeNetworkInterfaces",
                status="query_failed",
                message=str(exc),
            )

        if should_collect_snapshot_policies:
            collect_snapshot_policy_associations(
                args,
                subscription,
                account_id,
                region_id,
                region_disks,
                details,
            )

    if details.ecs_security_groups:
        print(
            f"[资产梳理] ECS安全组规则补采中 订阅={subscription.label} "
            f"安全组数={len(details.ecs_security_groups)}",
            file=sys.stderr,
        )
    for group in details.ecs_security_groups:
        if not group.get("security_group_id"):
            continue
        try:
            data = run_aliyun(
                [
                    "ecs",
                    "DescribeSecurityGroupAttribute",
                    "--RegionId",
                    group["region_id"],
                    "--SecurityGroupId",
                    group["security_group_id"],
                ],
                profile=subscription.profile,
                region=args.region or group["region_id"],
                timeout=args.timeout,
            )
            permissions = extract_nested_list(data, ("Permissions", "Permission"))
            details.ecs_security_group_rules.extend(
                normalize_ecs_security_group_rule(item, group) for item in permissions
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] ECS安全组规则获取失败 订阅={subscription.label} "
                f"地域={group['region_id']} 安全组={group['security_group_id']} 错误={exc}",
                file=sys.stderr,
            )

    print(f"[资产梳理] VPC详情补采中 订阅={subscription.label}", file=sys.stderr)
    collect_vpc_details(args, subscription, account_id, vpc_regions, details)
    print(f"[资产梳理] 负载均衡详情补采中 订阅={subscription.label}", file=sys.stderr)
    collect_slb_details(args, subscription, account_id, slb_regions, alb_regions, nlb_regions, details)
    print(f"[资产梳理] 数据库详情补采中 订阅={subscription.label}", file=sys.stderr)
    collect_database_details(args, subscription, account_id, raw_rows, details)
    print(f"[资产梳理] RAM详情补采中 订阅={subscription.label}", file=sys.stderr)
    collect_ram_details(args, subscription, account_id, details)
    print(f"[资产梳理] OSS元数据补采中 订阅={subscription.label}", file=sys.stderr)
    collect_oss_details(args, subscription, raw_rows, details)
    if checks_config is not None and checks_config.metric_checks_enabled:
        print(f"[资产梳理] 云监控指标补采中 订阅={subscription.label}", file=sys.stderr)
        collect_metric_details(args, subscription, account_id, checks_config, details)
    print(f"[资产梳理] 云安全中心漏洞补采中 订阅={subscription.label}", file=sys.stderr)
    collect_sas_vulnerability_details(args, subscription, account_id, details)
    print(f"[资产梳理] 详情补采完成 订阅={subscription.label}", file=sys.stderr)
    return details


def collect_snapshot_policy_associations(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    region_id: str,
    disks: list[dict[str, str]],
    details: DetailedAssets,
) -> None:
    if disks:
        print(
            f"[资产梳理] ECS自动快照策略关联补采中 订阅={subscription.label} "
            f"地域={region_id} 云盘数={len(disks)}",
            file=sys.stderr,
        )
    for disk in disks:
        disk_id = disk.get("disk_id", "")
        if not disk_id:
            continue
        try:
            associations = next_token_rpc_api(
                args,
                subscription,
                "ecs",
                "DescribeAutoSnapshotPolicyAssociations",
                region_id,
                [("AutoSnapshotPolicyAssociations", "AutoSnapshotPolicyAssociation")],
                extra_args=["--DiskId", disk_id],
            )
            details.ecs_snapshot_policy_associations.extend(
                normalize_snapshot_policy_association(item, subscription, account_id, region_id)
                for item in associations
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] ECS自动快照策略关联获取失败 订阅={subscription.label} "
                f"地域={region_id} 云盘={disk_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="ecs",
                api="DescribeAutoSnapshotPolicyAssociations",
                status="query_failed",
                message=str(exc),
                resource_id=disk_id,
            )


def split_ids(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def collect_vpc_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    regions: list[str],
    details: DetailedAssets,
) -> None:
    for region_id in [region for region in regions if region]:
        try:
            vswitches = paged_rpc_api(
                args,
                subscription,
                "vpc",
                "DescribeVSwitches",
                region_id,
                [("VSwitches", "VSwitch")],
                page_size=50,
            )
            details.vpc_vswitches.extend(
                normalize_vswitch(item, subscription, account_id, region_id)
                for item in vswitches
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] VSwitch详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="vpc",
                api="DescribeVSwitches",
                status="query_failed",
                message=str(exc),
            )

        try:
            eips = paged_rpc_api(
                args,
                subscription,
                "vpc",
                "DescribeEipAddresses",
                region_id,
                [("EipAddresses", "EipAddress")],
                page_size=50,
            )
            details.vpc_eips.extend(
                normalize_vpc_eip(item, subscription, account_id, region_id)
                for item in eips
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] EIP详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="vpc",
                api="DescribeEipAddresses",
                status="query_failed",
                message=str(exc),
            )

        try:
            nat_gateways = paged_rpc_api(
                args,
                subscription,
                "vpc",
                "DescribeNatGateways",
                region_id,
                [("NatGateways", "NatGateway")],
                page_size=50,
            )
            region_nats = [
                normalize_nat_gateway(item, subscription, account_id, region_id)
                for item in nat_gateways
            ]
            details.vpc_nat_gateways.extend(region_nats)
            collect_nat_rules(args, subscription, account_id, region_id, region_nats, details)
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] NAT详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="vpc",
                api="DescribeNatGateways",
                status="query_failed",
                message=str(exc),
            )

        try:
            vpn_gateways = paged_rpc_api(
                args,
                subscription,
                "vpc",
                "DescribeVpnGateways",
                region_id,
                [("VpnGateways", "VpnGateway")],
                page_size=50,
            )
            details.vpc_vpn_gateways.extend(
                normalize_vpn_gateway(item, subscription, account_id, region_id)
                for item in vpn_gateways
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] VPN网关详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="vpn",
                api="DescribeVpnGateways",
                status="query_failed",
                message=str(exc),
            )

        try:
            vpn_connections = paged_rpc_api(
                args,
                subscription,
                "vpc",
                "DescribeVpnConnections",
                region_id,
                [("VpnConnections", "VpnConnection")],
                page_size=50,
            )
            details.vpc_vpn_connections.extend(
                normalize_vpn_connection(item, subscription, account_id, region_id)
                for item in vpn_connections
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] VPN连接详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="vpn",
                api="DescribeVpnConnections",
                status="query_failed",
                message=str(exc),
            )

        try:
            ssl_vpn_servers = paged_rpc_api(
                args,
                subscription,
                "vpc",
                "DescribeSslVpnServers",
                region_id,
                [("SslVpnServers", "SslVpnServer")],
                page_size=50,
            )
            details.vpc_ssl_vpn_servers.extend(
                normalize_ssl_vpn_server(item, subscription, account_id, region_id)
                for item in ssl_vpn_servers
            )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] SSL-VPN服务端详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="vpn",
                api="DescribeSslVpnServers",
                status="query_failed",
                message=str(exc),
            )


def collect_nat_rules(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    region_id: str,
    nat_gateways: list[dict[str, str]],
    details: DetailedAssets,
) -> None:
    for nat in nat_gateways:
        nat_id = nat.get("nat_gateway_id", "")
        for snat_table_id in split_ids(nat.get("snat_table_ids", "")):
            try:
                entries = paged_rpc_api(
                    args,
                    subscription,
                    "vpc",
                    "DescribeSnatTableEntries",
                    region_id,
                    [("SnatTableEntries", "SnatTableEntry")],
                    extra_args=["--SnatTableId", snat_table_id],
                    page_size=50,
                )
                details.vpc_snat_entries.extend(
                    normalize_nat_rule(item, nat_id, subscription, account_id, region_id)
                    for item in entries
                )
            except (AliyunCliError, subprocess.TimeoutExpired):
                details.vpc_snat_entries.append(
                    {
                        "subscription": subscription.label,
                        "account_id": account_id,
                        "region_id": region_id,
                        "nat_gateway_id": nat_id,
                        "resource_id": snat_table_id,
                        "status": "query_failed",
                    }
                )
                continue

        for forward_table_id in split_ids(nat.get("forward_table_ids", "")):
            try:
                entries = paged_rpc_api(
                    args,
                    subscription,
                    "vpc",
                    "DescribeForwardTableEntries",
                    region_id,
                    [("ForwardTableEntries", "ForwardTableEntry")],
                    extra_args=["--ForwardTableId", forward_table_id],
                    page_size=50,
                )
                details.vpc_dnat_entries.extend(
                    normalize_nat_rule(item, nat_id, subscription, account_id, region_id)
                    for item in entries
                )
            except (AliyunCliError, subprocess.TimeoutExpired):
                details.vpc_dnat_entries.append(
                    {
                        "subscription": subscription.label,
                        "account_id": account_id,
                        "region_id": region_id,
                        "nat_gateway_id": nat_id,
                        "resource_id": forward_table_id,
                        "status": "query_failed",
                    }
                )
                continue


def collect_slb_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    slb_regions: list[str],
    alb_regions: list[str],
    nlb_regions: list[str],
    details: DetailedAssets,
) -> None:
    collect_clb_details(args, subscription, account_id, slb_regions, details)
    collect_alb_details(args, subscription, account_id, alb_regions, details)
    collect_nlb_details(args, subscription, account_id, nlb_regions, details)


def collect_clb_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    regions: list[str],
    details: DetailedAssets,
) -> None:
    for region_id in [region for region in regions if region]:
        try:
            load_balancers = paged_rpc_api(
                args,
                subscription,
                "slb",
                "DescribeLoadBalancers",
                region_id,
                [("LoadBalancers", "LoadBalancer")],
            )
            region_lbs = [
                normalize_load_balancer(item, subscription, account_id, region_id)
                for item in load_balancers
            ]
            details.slb_load_balancers.extend(region_lbs)
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] SLB详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="slb",
                api="DescribeLoadBalancers",
                status="query_failed",
                message=str(exc),
            )
            continue

        try:
            listeners = next_token_rpc_api(
                args,
                subscription,
                "slb",
                "DescribeLoadBalancerListeners",
                region_id,
                [("Listeners",), ("Listeners", "Listener")],
            )
            details.slb_listeners.extend(
                normalize_listener(item, subscription, account_id, region_id)
                for item in listeners
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            for lb in region_lbs:
                details.slb_listeners.append(
                    {
                        "subscription": subscription.label,
                        "account_id": account_id,
                        "region_id": region_id,
                        "load_balancer_id": lb["load_balancer_id"],
                        "resource_id": lb["load_balancer_id"],
                        "status": "query_failed",
                    }
                )


def collect_alb_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    regions: list[str],
    details: DetailedAssets,
) -> None:
    for region_id in [region for region in regions if region]:
        region_lbs: list[dict[str, str]] = []
        try:
            load_balancers = next_token_rpc_api(
                args,
                subscription,
                "alb",
                "ListLoadBalancers",
                region_id,
                [("LoadBalancers",)],
                include_region_id=False,
            )
            region_lbs = [
                normalize_load_balancer(item, subscription, account_id, region_id)
                for item in load_balancers
            ]
            details.alb_load_balancers.extend(region_lbs)
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] ALB详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="alb",
                api="ListLoadBalancers",
                status="query_failed",
                message=str(exc),
            )

        try:
            listeners = next_token_rpc_api(
                args,
                subscription,
                "alb",
                "ListListeners",
                region_id,
                [("Listeners",)],
                include_region_id=False,
            )
            details.alb_listeners.extend(
                normalize_listener(item, subscription, account_id, region_id)
                for item in listeners
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            print(
                f"[资产梳理] ALB监听详情获取失败 订阅={subscription.label} "
                f"地域={region_id}",
                file=sys.stderr,
            )
            details.alb_listeners.extend(
                {
                    "subscription": subscription.label,
                    "account_id": account_id,
                    "region_id": region_id,
                    "load_balancer_id": lb.get("load_balancer_id", ""),
                    "resource_id": lb.get("load_balancer_id", ""),
                    "status": "query_failed",
                }
                for lb in region_lbs
            )

        try:
            server_groups = next_token_rpc_api(
                args,
                subscription,
                "alb",
                "ListServerGroups",
                region_id,
                [("ServerGroups",)],
                include_region_id=False,
            )
            region_groups = [
                normalize_server_group(item, subscription, account_id, region_id)
                for item in server_groups
            ]
            details.alb_server_groups.extend(region_groups)
            collect_server_group_servers(
                args,
                subscription,
                "alb",
                region_id,
                account_id,
                region_groups,
                details.alb_server_group_servers,
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            print(
                f"[资产梳理] ALB服务器组详情获取失败 订阅={subscription.label} "
                f"地域={region_id}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="alb",
                api="ListServerGroups",
                status="query_failed",
                message="ALB服务器组详情获取失败",
            )


def collect_nlb_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    regions: list[str],
    details: DetailedAssets,
) -> None:
    for region_id in [region for region in regions if region]:
        region_lbs: list[dict[str, str]] = []
        try:
            load_balancers = next_token_rpc_api(
                args,
                subscription,
                "nlb",
                "ListLoadBalancers",
                region_id,
                [("LoadBalancers",)],
            )
            region_lbs = [
                normalize_load_balancer(item, subscription, account_id, region_id)
                for item in load_balancers
            ]
            details.nlb_load_balancers.extend(region_lbs)
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] NLB详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="nlb",
                api="ListLoadBalancers",
                status="query_failed",
                message=str(exc),
            )

        try:
            listeners = next_token_rpc_api(
                args,
                subscription,
                "nlb",
                "ListListeners",
                region_id,
                [("Listeners",)],
            )
            details.nlb_listeners.extend(
                normalize_listener(item, subscription, account_id, region_id)
                for item in listeners
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            print(
                f"[资产梳理] NLB监听详情获取失败 订阅={subscription.label} "
                f"地域={region_id}",
                file=sys.stderr,
            )
            details.nlb_listeners.extend(
                {
                    "subscription": subscription.label,
                    "account_id": account_id,
                    "region_id": region_id,
                    "load_balancer_id": lb.get("load_balancer_id", ""),
                    "resource_id": lb.get("load_balancer_id", ""),
                    "status": "query_failed",
                }
                for lb in region_lbs
            )

        try:
            server_groups = next_token_rpc_api(
                args,
                subscription,
                "nlb",
                "ListServerGroups",
                region_id,
                [("ServerGroups",)],
            )
            region_groups = [
                normalize_server_group(item, subscription, account_id, region_id)
                for item in server_groups
            ]
            details.nlb_server_groups.extend(region_groups)
            collect_server_group_servers(
                args,
                subscription,
                "nlb",
                region_id,
                account_id,
                region_groups,
                details.nlb_server_group_servers,
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            print(
                f"[资产梳理] NLB服务器组详情获取失败 订阅={subscription.label} "
                f"地域={region_id}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="nlb",
                api="ListServerGroups",
                status="query_failed",
                message="NLB服务器组详情获取失败",
            )


def collect_server_group_servers(
    args: argparse.Namespace,
    subscription: Subscription,
    service: str,
    region_id: str,
    account_id: str,
    server_groups: list[dict[str, str]],
    output: list[dict[str, str]],
) -> None:
    for group in server_groups:
        group_id = group.get("server_group_id", "")
        if not group_id:
            continue
        try:
            servers = next_token_rpc_api(
                args,
                subscription,
                service,
                "ListServerGroupServers",
                region_id,
                [("Servers",)],
                extra_args=["--ServerGroupId", group_id],
                include_region_id=(service != "alb"),
            )
            output.extend(
                normalize_server_group_server(item, subscription, account_id, region_id, group_id)
                for item in servers
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            output.append(
                {
                    "subscription": subscription.label,
                    "account_id": account_id,
                    "region_id": region_id,
                    "server_group_id": group_id,
                    "resource_id": group_id,
                    "status": "query_failed",
                }
            )
            continue


def collect_ram_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    details: DetailedAssets,
) -> None:
    try:
        users = marker_rpc_api(args, subscription, "ram", "ListUsers", [("Users", "User")])
        details.ram_users.extend(normalize_ram_user(item, subscription, account_id) for item in users)
    except (AliyunCliError, subprocess.TimeoutExpired) as exc:
        print(f"[资产梳理] RAM用户详情获取失败 订阅={subscription.label} 错误={exc}", file=sys.stderr)
        users = []

    for item in users:
        user_name = str(pick(item, "UserName"))
        if not user_name:
            continue
        try:
            keys = marker_rpc_api(
                args,
                subscription,
                "ram",
                "ListAccessKeys",
                [("AccessKeys", "AccessKey")],
                extra_args=["--UserName", user_name],
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            keys = []

        for key in keys:
            last_used = {}
            access_key_id = str(pick(key, "AccessKeyId"))
            if access_key_id:
                try:
                    last_used_data = run_aliyun(
                        ["ram", "GetAccessKeyLastUsed", "--UserAccessKeyId", access_key_id],
                        profile=subscription.profile,
                        region=args.region,
                        timeout=args.timeout,
                    )
                    last_used = (
                        last_used_data.get("AccessKeyLastUsed")
                        if isinstance(last_used_data.get("AccessKeyLastUsed"), dict)
                        else {}
                    )
                except (AliyunCliError, subprocess.TimeoutExpired):
                    last_used = {"QueryFailed": "true"}
            details.ram_access_keys.append(
                normalize_ram_access_key(key, subscription, account_id, user_name, last_used)
            )

        try:
            mfa_data = run_aliyun(
                ["ram", "GetUserMFAInfo", "--UserName", user_name],
                profile=subscription.profile,
                region=args.region,
                timeout=args.timeout,
            )
            details.ram_user_mfa.append(normalize_ram_mfa(mfa_data, subscription, account_id, user_name))
        except (AliyunCliError, subprocess.TimeoutExpired):
            details.ram_user_mfa.append(
                normalize_ram_mfa({}, subscription, account_id, user_name)
            )

    try:
        groups = marker_rpc_api(args, subscription, "ram", "ListGroups", [("Groups", "Group")])
        details.ram_groups.extend(normalize_ram_group(item, subscription, account_id) for item in groups)
    except (AliyunCliError, subprocess.TimeoutExpired) as exc:
        print(f"[资产梳理] RAM用户组详情获取失败 订阅={subscription.label} 错误={exc}", file=sys.stderr)
        groups = []

    for item in groups:
        group_name = str(pick(item, "GroupName"))
        if not group_name:
            continue
        try:
            users_for_group = marker_rpc_api(
                args,
                subscription,
                "ram",
                "ListUsersForGroup",
                [("Users", "User")],
                extra_args=["--GroupName", group_name],
            )
            details.ram_group_users.extend(
                normalize_ram_group_user(user, subscription, account_id, group_name)
                for user in users_for_group
            )
        except (AliyunCliError, subprocess.TimeoutExpired):
            details.ram_group_users.append(
                {
                    "subscription": subscription.label,
                    "account_id": account_id,
                    "region_id": "global",
                    "group_name": group_name,
                    "user_name": "query_failed",
                    "resource_id": group_name,
                }
            )
            continue


def collect_oss_details(
    args: argparse.Namespace,
    subscription: Subscription,
    raw_rows: list[dict[str, str]],
    details: DetailedAssets,
) -> None:
    bucket_rows = [
        row
        for row in raw_rows
        if row.get("resource_type") == "ACS::OSS::Bucket"
        or row.get("service_code") == "oss"
    ]
    seen: set[str] = set()
    for row in bucket_rows:
        bucket_name = row.get("resource_name") or row.get("resource_id")
        if not bucket_name or bucket_name in seen:
            continue
        seen.add(bucket_name)
        metadata = get_oss_bucket_metadata(args, subscription, bucket_name)
        details.oss_buckets.append(normalize_oss_bucket(row, metadata))


def get_oss_bucket_metadata(
    args: argparse.Namespace,
    subscription: Subscription,
    bucket_name: str,
) -> dict[str, str]:
    metadata = {
        "acl": "",
        "encryption_algorithm": "",
        "policy_public": "",
        "public_access_block": "",
        "lifecycle_configured": "",
        "lifecycle_query_failed": "",
    }

    try:
        data = run_aliyun(
            ["oss", "GetBucketAcl", "--BucketName", bucket_name],
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )
        metadata["acl"] = str(
            pick_path(data, "AccessControlPolicy", "AccessControlList", "Grant")
            or pick(data, "Acl", "ACL")
        )
    except (AliyunCliError, subprocess.TimeoutExpired):
        metadata["acl"] = ""

    try:
        data = run_aliyun(
            ["oss", "GetBucketEncryption", "--BucketName", bucket_name],
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )
        metadata["encryption_algorithm"] = str(
            pick_path(data, "ServerSideEncryptionRule", "SSEAlgorithm")
            or pick(data, "SSEAlgorithm", "Algorithm")
        )
    except (AliyunCliError, subprocess.TimeoutExpired):
        metadata["encryption_algorithm"] = ""

    try:
        data = run_aliyun(
            ["oss", "GetBucketPolicyStatus", "--BucketName", bucket_name],
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )
        metadata["policy_public"] = str(
            pick_path(data, "PolicyStatus", "IsPublic")
            or pick(data, "IsPublic")
        ).lower()
    except (AliyunCliError, subprocess.TimeoutExpired):
        metadata["policy_public"] = ""

    try:
        data = run_aliyun(
            ["oss", "GetBucketPublicAccessBlock", "--BucketName", bucket_name],
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )
        metadata["public_access_block"] = str(
            pick_path(data, "PublicAccessBlockConfiguration", "BlockPublicAccess")
            or pick(data, "BlockPublicAccess")
        ).lower()
    except (AliyunCliError, subprocess.TimeoutExpired):
        metadata["public_access_block"] = ""

    try:
        data = run_aliyun(
            ["oss", "GetBucketLifecycle", "--BucketName", bucket_name],
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )
        rules = extract_nested_list(data, ("LifecycleConfiguration", "Rule"), ("Rules", "Rule"))
        metadata["lifecycle_configured"] = "true" if rules else "false"
    except AliyunCliError as exc:
        metadata["lifecycle_configured"] = "false"
        metadata["lifecycle_query_failed"] = (
            "false" if looks_missing_configuration(exc) else "true"
        )
    except subprocess.TimeoutExpired:
        metadata["lifecycle_configured"] = "false"
        metadata["lifecycle_query_failed"] = "true"

    return metadata


def looks_missing_configuration(error: AliyunCliError) -> bool:
    text = f"{error.stdout}\n{error.stderr}".lower()
    markers = ("nosuch", "not exist", "not found", "not configured", "不存在", "没有配置")
    return any(marker in text for marker in markers)


def collect_database_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    raw_rows: list[dict[str, str]],
    details: DetailedAssets,
) -> None:
    rds_regions = regions_from_rows(raw_rows, "rds")
    redis_regions = sorted(set(regions_from_rows(raw_rows, "kvstore")) | set(regions_from_rows(raw_rows, "redis")))

    for region_id in rds_regions:
        try:
            instances = paged_rpc_api(
                args,
                subscription,
                "rds",
                "DescribeDBInstances",
                region_id,
                [("Items", "DBInstance"), ("DBInstances", "DBInstance")],
            )
            region_instances = [
                normalize_rds_instance(item, subscription, account_id, region_id)
                for item in instances
            ]
            details.rds_instances.extend(region_instances)
            for instance in region_instances:
                collect_db_net_infos(
                    args,
                    subscription,
                    "rds",
                    "DescribeDBInstanceNetInfo",
                    "--DBInstanceId",
                    instance,
                    details.rds_net_infos,
                )
                collect_rds_ip_arrays(
                    args,
                    subscription,
                    account_id,
                    instance,
                    details.rds_ip_arrays,
                )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] RDS详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="rds",
                api="DescribeDBInstances",
                status="query_failed",
                message=str(exc),
            )

    for region_id in redis_regions:
        try:
            instances = paged_rpc_api(
                args,
                subscription,
                "r-kvstore",
                "DescribeInstances",
                region_id,
                [("Instances", "KVStoreInstance"), ("Instances", "Instance")],
            )
            region_instances = [
                normalize_redis_instance(item, subscription, account_id, region_id)
                for item in instances
            ]
            details.redis_instances.extend(region_instances)
            for instance in region_instances:
                collect_db_net_infos(
                    args,
                    subscription,
                    "r-kvstore",
                    "DescribeDBInstanceNetInfo",
                    "--InstanceId",
                    instance,
                    details.redis_net_infos,
                )
        except (AliyunCliError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] Redis/Tair详情获取失败 订阅={subscription.label} "
                f"地域={region_id} 错误={exc}",
                file=sys.stderr,
            )
            record_collection_event(
                details,
                subscription,
                account_id=account_id,
                region_id=region_id,
                service="redis",
                api="DescribeInstances",
                status="query_failed",
                message=str(exc),
            )


def collect_db_net_infos(
    args: argparse.Namespace,
    subscription: Subscription,
    service: str,
    api_name: str,
    id_arg_name: str,
    instance: dict[str, str],
    output: list[dict[str, str]],
) -> None:
    instance_id = instance.get("instance_id", "")
    if not instance_id:
        return
    try:
        data = run_aliyun(
            [service, api_name, id_arg_name, instance_id],
            profile=subscription.profile,
            region=args.region or instance.get("region_id"),
            timeout=args.timeout,
        )
        items = extract_nested_list(
            data,
            ("DBInstanceNetInfos", "DBInstanceNetInfo"),
            ("NetInfoItems", "NetInfoItem"),
            ("Items", "DBInstanceNetInfo"),
        )
        output.extend(normalize_db_net_info(item, instance, service) for item in items)
    except (AliyunCliError, subprocess.TimeoutExpired):
        output.append(
            {
                **instance,
                "net_type": "query_failed",
                "connection_string": "",
                "port": "",
            }
        )


def collect_rds_ip_arrays(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    instance: dict[str, str],
    output: list[dict[str, str]],
) -> None:
    instance_id = instance.get("instance_id", "")
    if not instance_id:
        return

    try:
        arrays = paged_rpc_api(
            args,
            subscription,
            "rds",
            "DescribeDBInstanceIPArrayList",
            instance.get("region_id", ""),
            [("Items", "DBInstanceIPArray")],
            extra_args=["--DBInstanceId", instance_id],
        )
        output.extend(
            normalize_rds_ip_array(item, subscription, account_id, instance.get("region_id", ""), instance)
            for item in arrays
        )
    except (AliyunCliError, subprocess.TimeoutExpired):
        output.append(
            {
                "subscription": subscription.label,
                "account_id": account_id,
                "region_id": instance.get("region_id", ""),
                "instance_id": instance_id,
                "resource_id": instance_id,
                "resource_name": instance.get("resource_name", ""),
                "whitelist_name": "",
                "whitelist_attribute": "",
                "security_ip_list": "",
                "security_ip_type": "",
                "status": "query_failed",
            }
        )


METRIC_PROBES = [
    {
        "check_id": "metric_idle_ecs",
        "metric_role": "ecs_cpu",
        "namespace": "acs_ecs_dashboard",
        "metric_name": "CPUUtilization",
        "resource_type": "云服务器",
        "service": "ecs",
        "dimension_key": "instanceId",
        "detail_list": "ecs_instances",
        "id_key": "instance_id",
        "name_key": "instance_name",
    },
    {
        "check_id": "metric_idle_ecs",
        "metric_role": "ecs_network_out",
        "namespace": "acs_ecs_dashboard",
        "metric_name": "InternetOutRate",
        "resource_type": "云服务器",
        "service": "ecs",
        "dimension_key": "instanceId",
        "detail_list": "ecs_instances",
        "id_key": "instance_id",
        "name_key": "instance_name",
    },
    {
        "check_id": "metric_idle_eip",
        "metric_role": "eip_traffic",
        "namespace": "acs_vpc_eip",
        "metric_name": "net_tx.rate",
        "resource_type": "弹性公网IP",
        "service": "eip",
        "dimension_key": "allocationId",
        "detail_list": "vpc_eips",
        "id_key": "allocation_id",
        "name_key": "ip_address",
    },
    {
        "check_id": "metric_idle_slb",
        "metric_role": "slb_qps",
        "namespace": "acs_slb_dashboard",
        "metric_name": "Qps",
        "resource_type": "负载均衡",
        "service": "slb",
        "dimension_key": "instanceId",
        "detail_list": "slb_load_balancers",
        "id_key": "load_balancer_id",
        "name_key": "load_balancer_name",
    },
    {
        "check_id": "metric_idle_rds",
        "metric_role": "rds_connections",
        "namespace": "acs_rds_dashboard",
        "metric_name": "MySQL_Sessions",
        "resource_type": "RDS实例",
        "service": "rds",
        "dimension_key": "instanceId",
        "detail_list": "rds_instances",
        "id_key": "instance_id",
        "name_key": "resource_name",
    },
    {
        "check_id": "metric_idle_redis",
        "metric_role": "redis_qps",
        "namespace": "acs_kvstore",
        "metric_name": "StandardAvgQPS",
        "resource_type": "Redis/Tair实例",
        "service": "redis",
        "dimension_key": "instanceId",
        "detail_list": "redis_instances",
        "id_key": "instance_id",
        "name_key": "resource_name",
    },
]


def collect_metric_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    config: ChecksConfig,
    details: DetailedAssets,
) -> None:
    total_queries = sum(
        len(getattr(details, str(probe["detail_list"]))) * len(config.metric_windows_days)
        for probe in METRIC_PROBES
        if config.is_enabled(str(probe["check_id"]))
    )
    done_queries = 0
    if total_queries:
        print(
            f"[资产梳理] 云监控指标任务数 订阅={subscription.label} "
            f"汇总查询={total_queries}",
            file=sys.stderr,
        )
    for probe in METRIC_PROBES:
        if not config.is_enabled(str(probe["check_id"])):
            continue
        for resource in getattr(details, str(probe["detail_list"])):
            resource_id = resource.get(str(probe["id_key"]), "")
            region_id = resource.get("region_id", "")
            if not resource_id or not region_id:
                continue
            for window_days in config.metric_windows_days:
                summary = query_metric_summary(
                    args,
                    subscription,
                    account_id,
                    region_id,
                    resource,
                    probe,
                    window_days,
                    config.metric_period_seconds,
                )
                details.metric_summaries.append(summary)
                done_queries += 1
                if done_queries == total_queries or done_queries % 10 == 0:
                    print(
                        f"[资产梳理] 云监控指标进度 订阅={subscription.label} "
                        f"{done_queries}/{total_queries}",
                        file=sys.stderr,
                    )


def collect_sas_vulnerability_details(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    details: DetailedAssets,
) -> None:
    total_rows = 0
    for vul_type in SAS_VUL_TYPES:
        page_number = 1
        while True:
            try:
                data = run_aliyun(
                    [
                        "sas",
                        "DescribeVulList",
                        "--Lang",
                        "zh",
                        "--Type",
                        vul_type,
                        "--StatusList",
                        "1",
                        "--CurrentPage",
                        str(page_number),
                        "--PageSize",
                        "100",
                    ],
                    profile=subscription.profile,
                    region=args.region,
                    timeout=args.timeout,
                )
            except (AliyunCliError, subprocess.TimeoutExpired) as exc:
                record_collection_event(
                    details,
                    subscription,
                    account_id=account_id,
                    region_id="global",
                    service="yundun-sas",
                    api="DescribeVulList",
                    status="query_failed",
                    message=f"漏洞列表查询失败 type={vul_type}: {exc}",
                )
                break

            records = extract_nested_list(data, ("VulRecords",))
            for record in records:
                details.sas_vulnerabilities.extend(
                    normalize_sas_vulnerability_rows(
                        record,
                        subscription,
                        account_id,
                        vul_type,
                    )
                )
            total_rows += len(records)

            total_count = int(data.get("TotalCount") or len(records))
            page_size = int(data.get("PageSize") or 100)
            if page_number * page_size >= total_count or not records:
                break
            page_number += 1

    print(
        f"[资产梳理] 云安全中心漏洞补采完成 订阅={subscription.label} "
        f"漏洞记录={total_rows} 导出行={len(details.sas_vulnerabilities)}",
        file=sys.stderr,
    )


def query_metric_summary(
    args: argparse.Namespace,
    subscription: Subscription,
    account_id: str,
    region_id: str,
    resource: dict[str, str],
    probe: dict[str, str],
    window_days: int,
    period_seconds: int,
) -> dict[str, str]:
    resource_id = resource.get(str(probe["id_key"]), "")
    resource_name = resource.get(str(probe["name_key"]), "") or resource_id
    values: list[float] = []
    query_failed = False
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=window_days)

    chunk_start = start
    while chunk_start < now:
        chunk_end = min(chunk_start + dt.timedelta(days=2), now)
        try:
            data = run_aliyun(
                [
                    "cms",
                    "DescribeMetricData",
                    "--Namespace",
                    str(probe["namespace"]),
                    "--MetricName",
                    str(probe["metric_name"]),
                    "--Dimensions",
                    f"{probe['dimension_key']}:{resource_id}",
                    "--StartTime",
                    str(int(chunk_start.timestamp() * 1000)),
                    "--EndTime",
                    str(int(chunk_end.timestamp() * 1000)),
                    "--Period",
                    str(period_seconds),
                    "--Length",
                    "1440",
                ],
                profile=subscription.profile,
                region=args.region or region_id,
                timeout=args.timeout,
            )
            values.extend(extract_metric_values(data))
        except (AliyunCliError, subprocess.TimeoutExpired):
            query_failed = True
            break
        chunk_start = chunk_end

    average = sum(values) / len(values) if values else 0.0
    maximum = max(values) if values else 0.0
    return normalize_metric_summary(
        subscription=subscription,
        account_id=account_id,
        region_id=region_id,
        service=str(probe["service"]),
        resource_type=str(probe["resource_type"]),
        resource_id=resource_id,
        resource_name=resource_name,
        check_id=str(probe["check_id"]),
        metric_role=str(probe["metric_role"]),
        namespace=str(probe["namespace"]),
        metric_name=str(probe["metric_name"]),
        window_days=window_days,
        average=average,
        maximum=maximum,
        datapoints=len(values),
        query_failed=query_failed,
    )


def extract_metric_values(data: dict[str, Any]) -> list[float]:
    datapoints = data.get("Datapoints", "")
    if isinstance(datapoints, str):
        try:
            parsed = json.loads(datapoints) if datapoints else []
        except json.JSONDecodeError:
            parsed = []
    else:
        parsed = datapoints

    values = []
    for item in parsed if isinstance(parsed, list) else []:
        if not isinstance(item, dict):
            continue
        for key in ("Average", "Value", "Maximum", "Sum"):
            value = item.get(key)
            if value in (None, ""):
                continue
            try:
                values.append(float(value))
                break
            except (TypeError, ValueError):
                continue
    return values


def search_resources(
    args: argparse.Namespace,
    subscription: Subscription,
) -> list[dict[str, str]]:
    scope = subscription.multi_account_scope or args.multi_account_scope
    api_name = "SearchMultiAccountResources" if scope else "SearchResources"
    max_results = 100 if scope else args.max_results
    rows: list[dict[str, str]] = []
    next_token = ""
    page = 0

    while True:
        page += 1
        cli_args = [
            "resourcecenter",
            api_name,
            "--MaxResults",
            str(max_results),
        ]
        if scope:
            cli_args.extend(["--Scope", scope])
        if args.search_expression:
            cli_args.extend(["--SearchExpression", args.search_expression])
        if args.include_deleted and not scope:
            cli_args.extend(["--IncludeDeletedResources", "true"])
        if args.resource_group_id and not scope:
            cli_args.extend(["--ResourceGroupId", args.resource_group_id])
        if next_token:
            cli_args.extend(["--NextToken", next_token])

        data = run_aliyun(
            cli_args,
            profile=subscription.profile,
            region=args.region,
            timeout=args.timeout,
        )

        resources = extract_resources(data)
        rows.extend(
            normalize_resource(item, api_name, subscription) for item in resources
        )

        if args.limit and len(rows) >= args.limit:
            return rows[: args.limit]

        next_token = str(data.get("NextToken") or data.get("nextToken") or "")
        print(
            f"[资产梳理] 订阅={subscription.label} 页码={page} "
            f"本页资源数={len(resources)} 累计资源数={len(rows)}",
            file=sys.stderr,
        )
        if not next_token:
            return rows
        if args.sleep_seconds > 0:
            time.sleep(args.sleep_seconds)


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    write_rows_csv(path, rows, [(column, column) for column in CSV_COLUMNS])


def write_rows_csv(
    path: Path,
    rows: list[dict[str, Any]],
    columns: list[tuple[str, str]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(
            fp,
            fieldnames=[key for key, _ in columns],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def read_raw_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        return [
            {key: str(value or "") for key, value in row.items()}
            for row in reader
        ]


def excel_column_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def clean_xml_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return xml_escape(text)


def clean_xml_attr(value: Any) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return xml_escape(text, {'"': "&quot;", "'": "&apos;"})


def xlsx_safe_sheet_name(name: str, used: set[str]) -> str:
    cleaned = re.sub(r"[\[\]:*?/\\]", "_", name).strip() or "Sheet"
    cleaned = cleaned[:31]
    candidate = cleaned
    suffix = 2
    while candidate in used:
        tail = f"_{suffix}"
        candidate = f"{cleaned[:31 - len(tail)]}{tail}"
        suffix += 1
    used.add(candidate)
    return candidate


def worksheet_xml(sheet: Sheet) -> str:
    rows_xml = []
    headers = [title for _, title in sheet.columns]
    data_rows = [dict(zip((key for key, _ in sheet.columns), headers))]
    data_rows.extend(sheet.rows)

    for row_index, row in enumerate(data_rows, start=1):
        cells = []
        style = ' s="1"' if row_index == 1 else ""
        for column_index, (key, _) in enumerate(sheet.columns, start=1):
            ref = f"{excel_column_name(column_index)}{row_index}"
            value = row.get(key, "")
            cells.append(
                f'<c r="{ref}" t="inlineStr"{style}><is><t>'
                f"{clean_xml_text(value)}</t></is></c>"
            )
        rows_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    col_count = len(sheet.columns)
    row_count = max(len(data_rows), 1)
    last_ref = f"{excel_column_name(col_count)}{row_count}"
    widths = "".join(
        f'<col min="{idx}" max="{idx}" width="18" customWidth="1"/>'
        for idx in range(1, col_count + 1)
    )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        f"<cols>{widths}</cols>"
        f'<sheetData>{"".join(rows_xml)}</sheetData>'
        f'<autoFilter ref="A1:{last_ref}"/>'
        "</worksheet>"
    )


def write_xlsx(path: Path, sheets: list[Sheet]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    used_names: set[str] = set()
    safe_sheets = [
        Sheet(xlsx_safe_sheet_name(sheet.name, used_names), sheet.columns, sheet.rows)
        for sheet in sheets
    ]

    workbook_sheets = []
    workbook_rels = []
    content_types = [
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]

    for idx, sheet in enumerate(safe_sheets, start=1):
        workbook_sheets.append(
            f'<sheet name="{clean_xml_attr(sheet.name)}" sheetId="{idx}" r:id="rId{idx}"/>'
        )
        workbook_rels.append(
            f'<Relationship Id="rId{idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )

    workbook_rels.append(
        f'<Relationship Id="rId{len(safe_sheets) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as xlsx:
        xlsx.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            f'{"".join(content_types)}</Types>',
        )
        xlsx.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/></Relationships>',
        )
        xlsx.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<sheets>{"".join(workbook_sheets)}</sheets></workbook>',
        )
        xlsx.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'{"".join(workbook_rels)}</Relationships>',
        )
        xlsx.writestr(
            "xl/styles.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="2"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FFEFEFEF"/>'
            '<bgColor indexed="64"/></patternFill></fill></fills>'
            '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
            "</styleSheet>",
        )
        for idx, sheet in enumerate(safe_sheets, start=1):
            xlsx.writestr(f"xl/worksheets/sheet{idx}.xml", worksheet_xml(sheet))


def build_summary_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str, str], int] = {}
    for row in rows:
        key = (
            row.get("subscription", ""),
            row.get("service_code", ""),
            row.get("service", ""),
            row.get("resource_type", ""),
            row.get("resource_type_name", ""),
        )
        counts[key] = counts.get(key, 0) + 1

    return [
        {
            "subscription": subscription,
            "service_code": service_code,
            "service": service,
            "resource_type": resource_type,
            "resource_type_name": resource_type_name,
            "count": count,
        }
        for (
            subscription,
            service_code,
            service,
            resource_type,
            resource_type_name,
        ), count in sorted(
            counts.items(), key=lambda item: (item[0][0], item[0][1], item[0][3])
        )
    ]


def filter_by_service(rows: list[dict[str, str]], services: set[str]) -> list[dict[str, str]]:
    return [row for row in rows if row.get("service_code") in services]


def filter_by_resource_type(
    rows: list[dict[str, str]],
    resource_types: set[str],
) -> list[dict[str, str]]:
    return [row for row in rows if row.get("resource_type") in resource_types]


def build_report_info_rows(
    raw_rows: list[dict[str, str]],
    details: DetailedAssets,
    generated_at: str,
) -> list[dict[str, str]]:
    subscriptions = sorted({row.get("subscription", "") for row in raw_rows if row.get("subscription")})
    accounts = sorted({row.get("account_id", "") for row in raw_rows if row.get("account_id")})
    regions = sorted({row.get("region_id", "") for row in raw_rows if row.get("region_id")})
    return [
        {"item": "报告生成时间", "value": generated_at},
        {"item": "订阅范围", "value": ";".join(subscriptions)},
        {"item": "账号ID", "value": ";".join(accounts)},
        {"item": "地域范围", "value": ";".join(regions)},
        {"item": "资源数量", "value": str(len(raw_rows))},
        {"item": "采集问题数量", "value": str(len(collection_event_rows(details)))},
        {
            "item": "权限边界",
            "value": "仅使用 RAM 只读元数据权限；不读取 OSS Object、SLS 日志正文、KMS 凭据值、ACK kubeconfig 或镜像仓库 Token。",
        },
        {
            "item": "巡检边界",
            "value": "报告只输出发现和建议，不自动修复，不修改云资源；指标类仅标记疑似闲置。",
        },
        {
            "item": "指标疑似闲置说明",
            "value": (
                "未采集到云监控指标时该工作表为空。默认关闭指标巡检；如需输出低使用率资源，"
                "请在 config/checks.example.json 中将“指标巡检.启用”设为 true。"
                if not details.metric_summaries
                else "已采集云监控指标，只有持续低于阈值的资源才会进入“指标疑似闲置”工作表。"
            ),
        },
    ]


def collection_event_rows(details: DetailedAssets) -> list[dict[str, str]]:
    rows = list(details.collection_events)
    rows.extend(
        collection_event_from_row(row, "vpc", "DescribeSnatTableEntries", "SNAT规则查询失败")
        for row in details.vpc_snat_entries
        if row.get("status") == "query_failed"
    )
    rows.extend(
        collection_event_from_row(row, "vpc", "DescribeForwardTableEntries", "DNAT规则查询失败")
        for row in details.vpc_dnat_entries
        if row.get("status") == "query_failed"
    )
    for listeners, service, api in (
        (details.slb_listeners, "slb", "DescribeLoadBalancerListeners"),
        (details.alb_listeners, "alb", "ListListeners"),
        (details.nlb_listeners, "nlb", "ListListeners"),
    ):
        rows.extend(
            collection_event_from_row(row, service, api, "负载均衡监听查询失败")
            for row in listeners
            if row.get("status") == "query_failed"
        )
    for servers, service in (
        (details.alb_server_group_servers, "alb"),
        (details.nlb_server_group_servers, "nlb"),
    ):
        rows.extend(
            collection_event_from_row(row, service, "ListServerGroupServers", "服务器组后端查询失败")
            for row in servers
            if row.get("status") == "query_failed"
        )
    rows.extend(
        collection_event_from_row(row, "ram", "ListUsersForGroup", "用户组成员查询失败")
        for row in details.ram_group_users
        if row.get("user_name") == "query_failed"
    )
    rows.extend(
        collection_event_from_row(row, "rds", "DescribeDBInstanceNetInfo", "RDS连接地址查询失败")
        for row in details.rds_net_infos
        if row.get("net_type") == "query_failed"
    )
    rows.extend(
        collection_event_from_row(row, "rds", "DescribeDBInstanceIPArrayList", "RDS白名单查询失败")
        for row in details.rds_ip_arrays
        if row.get("status") == "query_failed"
    )
    rows.extend(
        collection_event_from_row(row, "redis", "DescribeDBInstanceNetInfo", "Redis连接地址查询失败")
        for row in details.redis_net_infos
        if row.get("net_type") == "query_failed"
    )
    rows.extend(
        collection_event_from_row(row, "oss", "GetBucketLifecycle", "OSS生命周期查询失败")
        for row in details.oss_buckets
        if row.get("lifecycle_query_failed") == "true"
    )
    rows.extend(
        collection_event_from_row(row, "cms", "DescribeMetricData", "云监控指标查询失败")
        for row in details.metric_summaries
        if row.get("query_failed") == "true"
    )
    rows.extend(
        {
            **collection_event_from_row(row, "cms", "DescribeMetricData", "云监控指标空返回"),
            "status": "empty",
        }
        for row in details.metric_summaries
        if row.get("query_failed") != "true" and row.get("datapoints") in {"", "0"}
    )
    return rows


def collection_event_from_row(
    row: dict[str, str],
    service: str,
    api: str,
    message: str,
) -> dict[str, str]:
    return {
        "subscription": row.get("subscription", ""),
        "account_id": row.get("account_id", ""),
        "region_id": row.get("region_id", ""),
        "service": display_with_name(service, SERVICE_NAMES),
        "api": api,
        "resource_id": row.get("resource_id") or row.get("load_balancer_id") or row.get("server_group_id") or row.get("bucket_name", ""),
        "status": "query_failed",
        "message": message,
    }


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def topology_label_lines(*parts: str) -> list[str]:
    return [part for part in parts if part]


def topology_dir_for(
    args: argparse.Namespace,
    subscription: Subscription,
    subscriptions_count: int,
) -> Path:
    del subscriptions_count
    base_dir = project_path(args.output_dir)
    return base_dir / safe_dirname(subscription.label) / "topology"


def merge_row(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    merged = dict(base)
    for key, value in extra.items():
        if value not in (None, ""):
            merged[key] = str(value)
    return merged


PLANTUML_KIND = {
    "root":           ("rectangle", "#E3F2FD"),
    "vswitch":         ("rectangle", "#C8E6C9"),
    "ecs":             ("node",      "#ADD8E6"),
    "eni":             ("node",      "#E0FFFF"),
    "eip":             ("node",      "#FF00FF"),
    "nat":             ("rectangle", "#BBDEFB"),
    "vpn_gateway":     ("rectangle", "#BBDEFB"),
    "vpn_connection":  ("rectangle", "#BBDEFB"),
    "ssl_vpn":         ("rectangle", "#BBDEFB"),
    "lb":              ("rectangle", "#BBDEFB"),
    "listener":        ("rectangle", "#D3D3D3"),
    "server_group":    ("rectangle", "#D3D3D3"),
    "backend":         ("node",      "#ADD8E6"),
    "rds":             ("database",  "#FFE0B2"),
    "redis":           ("database",  "#FFCDD2"),
}


def plantuml_alias(*parts: str) -> str:
    """生成 PlantUML 别名，只保留字母数字和下划线。"""
    joined = "_".join(part for part in parts if part)
    cleaned = re.sub(r"[^0-9A-Za-z_]+", "_", joined).strip("_")
    return cleaned or "node"


def plantuml_label(*parts: str) -> str:
    """生成 PlantUML 显示标签，多行用 \\n 拼接。"""
    lines = topology_label_lines(*parts)
    return "\\n".join(lines).replace('"', "'")


def resource_display_name(row: dict[str, str], name_keys: tuple[str, ...], id_keys: tuple[str, ...]) -> str:
    for key in name_keys:
        if row.get(key):
            return row[key]
    for key in id_keys:
        if row.get(key):
            return row[key]
    return "未命名资源"


def summarize_security_groups(value: str) -> str:
    groups = split_ids(value)
    if not groups:
        return ""
    if len(groups) <= 3:
        return ",".join(groups)
    return f"{','.join(groups[:3])} 等{len(groups)}个"


def build_vpc_bucket(vpc_row: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "vpc": vpc_row or {},
        "resource_ids": set(),
        "vswitches": [],
        "ecs": [],
        "enis": [],
        "eips": [],
        "nats": [],
        "vpn_gateways": [],
        "vpn_connections": [],
        "ssl_vpn_servers": [],
        "lbs": [],
        "listeners": [],
        "server_groups": [],
        "server_group_servers": [],
        "rds": [],
        "redis": [],
    }


def add_bucket_row(
    bucket: dict[str, Any],
    kind: str,
    row: dict[str, str],
    *,
    resource_keys: tuple[str, ...],
) -> None:
    bucket[kind].append(row)
    for key in resource_keys:
        value = row.get(key, "")
        if value:
            bucket["resource_ids"].add(value)
    resource_id = row.get("resource_id", "")
    if resource_id:
        bucket["resource_ids"].add(resource_id)


def topology_collection_events(
    details: DetailedAssets,
    *,
    region_id: str = "",
    resource_ids: set[str] | None = None,
) -> list[dict[str, str]]:
    events = []
    for row in collection_event_rows(details):
        if row.get("api", "") not in TOPOLOGY_RELEVANT_APIS:
            continue
        if region_id and row.get("region_id", "") not in {"", region_id}:
            continue
        resource_id = row.get("resource_id", "")
        if resource_ids and resource_id and resource_id not in resource_ids:
            continue
        events.append(row)
    return events


def collect_topology_buckets(
    raw_rows: list[dict[str, str]],
    details: DetailedAssets,
) -> TopologyBuckets:
    subscription = next((row.get("subscription", "") for row in raw_rows if row.get("subscription")), "")
    raw_vpcs = {
        row.get("resource_id", ""): row
        for row in filter_by_resource_type(raw_rows, {"ACS::VPC::VPC"})
        if row.get("resource_id")
    }
    raw_vswitches = {
        row.get("resource_id", ""): row
        for row in filter_by_resource_type(raw_rows, {"ACS::VPC::VSwitch"})
        if row.get("resource_id")
    }
    vswitches: dict[str, dict[str, str]] = {}
    for vswitch_id, row in raw_vswitches.items():
        vswitches[vswitch_id] = dict(row)
        vswitches[vswitch_id]["vswitch_id"] = vswitch_id
    for row in details.vpc_vswitches:
        vswitch_id = row.get("vswitch_id") or row.get("resource_id")
        if not vswitch_id:
            continue
        existing = vswitches.get(vswitch_id, {})
        vswitches[vswitch_id] = merge_row(existing, row)

    rds_net_infos_by_instance: dict[str, list[dict[str, str]]] = {}
    for row in details.rds_net_infos:
        instance_id = row.get("instance_id", "")
        if instance_id:
            rds_net_infos_by_instance.setdefault(instance_id, []).append(row)

    redis_net_infos_by_instance: dict[str, list[dict[str, str]]] = {}
    for row in details.redis_net_infos:
        instance_id = row.get("instance_id", "")
        if instance_id:
            redis_net_infos_by_instance.setdefault(instance_id, []).append(row)

    instance_to_vpc = {
        row.get("instance_id", ""): row.get("vpc_id", "")
        for row in details.ecs_instances
        if row.get("instance_id") and row.get("vpc_id")
    }
    instance_to_vswitch = {
        row.get("instance_id", ""): row.get("vswitch_id", "")
        for row in details.ecs_instances
        if row.get("instance_id") and row.get("vswitch_id")
    }
    vswitch_to_vpc = {
        row.get("vswitch_id") or row.get("resource_id", ""): row.get("vpc_id", "")
        for row in vswitches.values()
        if (row.get("vswitch_id") or row.get("resource_id")) and row.get("vpc_id")
    }

    resource_to_vpc: dict[str, str] = {}

    def register_vpc(resource_id: str, vpc_id: str) -> None:
        if resource_id and vpc_id:
            resource_to_vpc[resource_id] = vpc_id

    for instance_id, vpc_id in instance_to_vpc.items():
        register_vpc(instance_id, vpc_id)
    for row in details.vpc_nat_gateways:
        register_vpc(row.get("nat_gateway_id", ""), row.get("vpc_id", ""))
    for row in details.vpc_vpn_gateways:
        register_vpc(row.get("vpn_gateway_id", ""), row.get("vpc_id", ""))
    for row in details.slb_load_balancers + details.alb_load_balancers + details.nlb_load_balancers:
        register_vpc(row.get("load_balancer_id", ""), row.get("vpc_id", ""))
    for row in details.alb_server_groups + details.nlb_server_groups:
        register_vpc(row.get("server_group_id", ""), row.get("vpc_id", ""))
    for row in details.rds_instances + details.redis_instances:
        register_vpc(row.get("instance_id", ""), row.get("vpc_id", ""))

    def resolve_vpc_id(row: dict[str, str]) -> str:
        if row.get("vpc_id"):
            return row["vpc_id"]
        vswitch_id = row.get("vswitch_id", "")
        if vswitch_id and vswitch_to_vpc.get(vswitch_id):
            return vswitch_to_vpc[vswitch_id]
        for key in (
            "instance_id",
            "associated_instance_id",
            "bind_resource_id",
            "load_balancer_id",
            "server_group_id",
            "vpn_gateway_id",
            "server_id",
            "resource_id",
        ):
            target_id = row.get(key, "")
            if target_id and resource_to_vpc.get(target_id):
                return resource_to_vpc[target_id]
        for target_id in split_ids(row.get("server_group_ids", "")):
            if resource_to_vpc.get(target_id):
                return resource_to_vpc[target_id]
        return ""

    def resolve_vswitch_id(row: dict[str, str]) -> str:
        if row.get("vswitch_id"):
            return row["vswitch_id"]
        for key in ("instance_id", "server_id", "resource_id"):
            target_id = row.get(key, "")
            if target_id and instance_to_vswitch.get(target_id):
                return instance_to_vswitch[target_id]
        return ""

    def add_row_to_bucket(
        groups: dict[str, dict[str, Any]],
        unassigned: dict[str, Any],
        kind: str,
        row: dict[str, str],
        *,
        resource_keys: tuple[str, ...],
    ) -> None:
        resolved_vpc_id = resolve_vpc_id(row)
        resolved_vswitch_id = resolve_vswitch_id(row)
        enriched = dict(row)
        enriched["_topology_vpc_id"] = resolved_vpc_id
        enriched["_topology_vswitch_id"] = resolved_vswitch_id
        if not resolved_vpc_id:
            add_bucket_row(unassigned, kind, enriched, resource_keys=resource_keys)
            return
        bucket = groups.setdefault(resolved_vpc_id, build_vpc_bucket(raw_vpcs.get(resolved_vpc_id)))
        if not bucket.get("vpc") and raw_vpcs.get(resolved_vpc_id):
            bucket["vpc"] = raw_vpcs[resolved_vpc_id]
        add_bucket_row(bucket, kind, enriched, resource_keys=resource_keys)

    groups = {
        vpc_id: build_vpc_bucket(row)
        for vpc_id, row in sorted(raw_vpcs.items(), key=lambda item: (item[1].get("region_id", ""), item[0]))
    }
    unassigned = build_vpc_bucket()

    for row in sorted(
        vswitches.values(),
        key=lambda item: (item.get("region_id", ""), item.get("vswitch_id", item.get("resource_id", ""))),
    ):
        add_row_to_bucket(groups, unassigned, "vswitches", row, resource_keys=("vswitch_id",))

    for row in details.ecs_instances:
        add_row_to_bucket(groups, unassigned, "ecs", row, resource_keys=("instance_id",))
    for row in details.ecs_network_interfaces:
        add_row_to_bucket(groups, unassigned, "enis", row, resource_keys=("network_interface_id", "instance_id"))
    for row in details.vpc_eips:
        add_row_to_bucket(
            groups,
            unassigned,
            "eips",
            row,
            resource_keys=("allocation_id", "instance_id", "associated_instance_id", "bind_resource_id"),
        )
    for row in details.vpc_nat_gateways:
        add_row_to_bucket(groups, unassigned, "nats", row, resource_keys=("nat_gateway_id",))
    for row in details.vpc_vpn_gateways:
        add_row_to_bucket(groups, unassigned, "vpn_gateways", row, resource_keys=("vpn_gateway_id",))
    for row in details.vpc_vpn_connections:
        add_row_to_bucket(groups, unassigned, "vpn_connections", row, resource_keys=("vpn_connection_id", "vpn_gateway_id"))
    for row in details.vpc_ssl_vpn_servers:
        add_row_to_bucket(groups, unassigned, "ssl_vpn_servers", row, resource_keys=("ssl_vpn_server_id", "vpn_gateway_id"))
    for service_code, rows in (
        ("slb", details.slb_load_balancers),
        ("alb", details.alb_load_balancers),
        ("nlb", details.nlb_load_balancers),
    ):
        for row in rows:
            add_row_to_bucket(
                groups,
                unassigned,
                "lbs",
                {**row, "service_code": service_code},
                resource_keys=("load_balancer_id",),
            )
    for service_code, rows in (
        ("slb", details.slb_listeners),
        ("alb", details.alb_listeners),
        ("nlb", details.nlb_listeners),
    ):
        for row in rows:
            add_row_to_bucket(
                groups,
                unassigned,
                "listeners",
                {**row, "service_code": service_code},
                resource_keys=("listener_id", "load_balancer_id"),
            )
    for service_code, rows in (("alb", details.alb_server_groups), ("nlb", details.nlb_server_groups)):
        for row in rows:
            add_row_to_bucket(
                groups,
                unassigned,
                "server_groups",
                {**row, "service_code": service_code},
                resource_keys=("server_group_id", "load_balancer_id"),
            )
    for service_code, rows in (
        ("alb", details.alb_server_group_servers),
        ("nlb", details.nlb_server_group_servers),
    ):
        for row in rows:
            add_row_to_bucket(
                groups,
                unassigned,
                "server_group_servers",
                {**row, "service_code": service_code},
                resource_keys=("server_group_id", "server_id"),
            )

    def build_database_row(
        row: dict[str, str],
        service_code: str,
        net_infos_by_instance: dict[str, list[dict[str, str]]],
    ) -> dict[str, str]:
        net_infos = net_infos_by_instance.get(row.get("instance_id", ""), [])
        vpc_candidates = sorted({resolve_vpc_id(item) for item in net_infos if resolve_vpc_id(item)})
        vswitch_candidates = sorted({resolve_vswitch_id(item) for item in net_infos if resolve_vswitch_id(item)})
        endpoint_values = []
        for item in net_infos:
            endpoint = item.get("connection_string", "")
            if item.get("port"):
                endpoint = f"{endpoint}:{item['port']}" if endpoint else item["port"]
            if endpoint:
                endpoint_values.append(endpoint)
        endpoint_summary = "; ".join(endpoint_values[:2])
        if len(endpoint_values) > 2:
            endpoint_summary = f"{endpoint_summary} 等{len(endpoint_values)}个地址"
        return {
            **row,
            "service_code": service_code,
            "vpc_id": row.get("vpc_id", "") or (vpc_candidates[0] if len(vpc_candidates) == 1 else ""),
            "vswitch_id": row.get("vswitch_id", "") or (vswitch_candidates[0] if len(vswitch_candidates) == 1 else ""),
            "endpoint_summary": endpoint_summary,
        }

    for row in details.rds_instances:
        add_row_to_bucket(
            groups,
            unassigned,
            "rds",
            build_database_row(row, "rds", rds_net_infos_by_instance),
            resource_keys=("instance_id",),
        )
    for row in details.redis_instances:
        add_row_to_bucket(
            groups,
            unassigned,
            "redis",
            build_database_row(row, "redis", redis_net_infos_by_instance),
            resource_keys=("instance_id",),
        )

    return TopologyBuckets(subscription=subscription, groups=groups, unassigned=unassigned)


def _plantuml_node_def(alias: str, kind: str, label: str) -> str:
    """生成单个 PlantUML 节点定义行。"""
    element, color = PLANTUML_KIND.get(kind, ("rectangle", ""))
    color_suffix = f" {color}" if color else ""
    return f'{element} "{label}" as {alias}{color_suffix}'


def render_bucket_plantuml(
    title: str,
    root_label: str,
    root_id: str,
    bucket: dict[str, Any],
    events: list[dict[str, str]],
) -> str:
    """将单个 VPC 桶渲染为 PlantUML 嵌入 Markdown 的拓扑文档。"""
    vpc_alias = plantuml_alias("VPC", root_id)
    vswitch_groups: dict[str, dict[str, Any]] = {}
    resource_nodes: dict[str, str] = {}
    root_nodes: dict[str, str] = {}
    edges: list[str] = []
    edge_seen: set[tuple[str, str]] = set()
    connected: set[str] = set()

    def add_edge(src: str, dst: str, label_text: str = "", dashed: bool = False) -> None:
        key = (src, dst)
        if not src or not dst or key in edge_seen:
            return
        edge_seen.add(key)
        connected.add(src)
        connected.add(dst)
        arrow = "..>" if dashed else "-->"
        if label_text:
            edges.append(f"{src} {arrow} {dst} : \"{label_text}\"")
        else:
            edges.append(f"{src} {arrow} {dst}")

    def register_resource_node(alias: str, row: dict[str, str], *keys: str) -> None:
        for key in keys:
            value = row.get(key, "")
            if value:
                resource_nodes[value] = alias

    def add_root_node(alias: str, kind: str, label: str) -> None:
        if alias not in root_nodes:
            root_nodes[alias] = _plantuml_node_def(alias, kind, label)

    def ensure_vswitch_group(row: dict[str, str]) -> str:
        vswitch_id = row.get("vswitch_id") or row.get("resource_id", "")
        if vswitch_id in vswitch_groups:
            return vswitch_groups[vswitch_id]["anchor_alias"]
        label_parts = [
            "VSwitch",
            resource_display_name(row, ("resource_name",), ("vswitch_id", "resource_id")),
        ]
        if row.get("cidr_block"):
            label_parts.append(row["cidr_block"])
        if row.get("zone_id"):
            label_parts.append(row["zone_id"])
        anchor_alias = plantuml_alias("VSW", vswitch_id)
        vswitch_groups[vswitch_id] = {
            "label": plantuml_label(*label_parts),
            "anchor_alias": anchor_alias,
            "nodes": {},
        }
        register_resource_node(anchor_alias, row, "vswitch_id", "resource_id")
        add_edge(vpc_alias, anchor_alias, "包含")
        return anchor_alias

    def attach_node(alias: str, kind: str, label: str, row: dict[str, str], *keys: str) -> None:
        vswitch_id = row.get("_topology_vswitch_id", "")
        if vswitch_id and vswitch_id in vswitch_groups:
            vswitch_groups[vswitch_id]["nodes"][alias] = _plantuml_node_def(alias, kind, label)
            register_resource_node(alias, row, *keys)
            add_edge(vswitch_groups[vswitch_id]["anchor_alias"], alias)
            return
        add_root_node(alias, kind, label)
        register_resource_node(alias, row, *keys)

    # VPC 根节点
    add_root_node(vpc_alias, "root", root_label)

    # VSwitch 子分组
    for row in bucket["vswitches"]:
        ensure_vswitch_group(row)

    # ECS
    for row in bucket["ecs"]:
        name = resource_display_name(row, ("instance_name",), ("instance_id",))
        alias = plantuml_alias("ECS", row.get("instance_id", ""))
        label_parts = ["ECS", name, row.get("instance_id", "")]
        if row.get("private_ip"):
            label_parts.append(f"私网: {row['private_ip']}")
        if row.get("public_ip"):
            label_parts.append(f"公网: {row['public_ip']}")
        if row.get("eip"):
            label_parts.append(f"EIP: {row['eip']}")
        security_groups = summarize_security_groups(row.get("security_group_ids", ""))
        if security_groups:
            label_parts.append(f"安全组: {security_groups}")
        attach_node(alias, "ecs", plantuml_label(*label_parts), row, "instance_id", "resource_id")

    # ENI
    for row in bucket["enis"]:
        instance_id = row.get("instance_id", "")
        if instance_id and resource_nodes.get(instance_id):
            continue
        alias = plantuml_alias("ENI", row.get("network_interface_id", ""))
        label_parts = [
            "ENI",
            resource_display_name(row, ("name",), ("network_interface_id", "resource_id")),
            row.get("network_interface_id", ""),
        ]
        if row.get("private_ip"):
            label_parts.append(f"私网: {row['private_ip']}")
        attach_node(alias, "eni", plantuml_label(*label_parts), row, "network_interface_id", "resource_id")

    # RDS / Redis
    for row in bucket["rds"] + bucket["redis"]:
        kind = "rds" if row.get("service_code") == "rds" else "redis"
        service_name = "RDS" if kind == "rds" else "Redis"
        alias = plantuml_alias(kind, row.get("instance_id", ""))
        label_parts = [
            service_name,
            resource_display_name(row, ("resource_name",), ("instance_id", "resource_id")),
            row.get("instance_id", ""),
        ]
        engine = " ".join(topology_label_lines(row.get("engine", ""), row.get("engine_version", "")))
        if engine:
            label_parts.append(engine)
        if row.get("endpoint_summary"):
            label_parts.append(row["endpoint_summary"])
        attach_node(alias, kind, plantuml_label(*label_parts), row, "instance_id", "resource_id")

    # NAT
    for row in bucket["nats"]:
        alias = plantuml_alias("NAT", row.get("nat_gateway_id", ""))
        label_parts = [
            "NAT",
            resource_display_name(row, ("resource_name",), ("nat_gateway_id", "resource_id")),
            row.get("nat_gateway_id", ""),
        ]
        if row.get("spec"):
            label_parts.append(f"规格: {row['spec']}")
        add_root_node(alias, "nat", plantuml_label(*label_parts))
        register_resource_node(alias, row, "nat_gateway_id", "resource_id")

    # VPN Gateway
    for row in bucket["vpn_gateways"]:
        alias = plantuml_alias("VPN_GW", row.get("vpn_gateway_id", ""))
        label_parts = [
            "VPN Gateway",
            resource_display_name(row, ("resource_name",), ("vpn_gateway_id", "resource_id")),
            row.get("vpn_gateway_id", ""),
        ]
        add_root_node(alias, "vpn_gateway", plantuml_label(*label_parts))
        register_resource_node(alias, row, "vpn_gateway_id", "resource_id")

    # LB (SLB/ALB/NLB)
    for row in bucket["lbs"]:
        service_name = row.get("service_code", "").upper() or "LB"
        alias = plantuml_alias("LB", row.get("load_balancer_id", ""))
        label_parts = [
            service_name,
            resource_display_name(row, ("load_balancer_name", "resource_name"), ("load_balancer_id", "resource_id")),
            row.get("load_balancer_id", ""),
        ]
        if row.get("address"):
            label_parts.append(row["address"])
        add_root_node(alias, "lb", plantuml_label(*label_parts))
        register_resource_node(alias, row, "load_balancer_id", "resource_id")

    # ServerGroup
    for row in bucket["server_groups"]:
        alias = plantuml_alias("SG", row.get("server_group_id", ""))
        label_parts = [
            "ServerGroup",
            resource_display_name(row, ("server_group_name", "resource_name"), ("server_group_id", "resource_id")),
            row.get("server_group_id", ""),
        ]
        protocol = " / ".join(topology_label_lines(row.get("server_group_type", ""), row.get("protocol", "")))
        if protocol:
            label_parts.append(protocol)
        add_root_node(alias, "server_group", plantuml_label(*label_parts))
        register_resource_node(alias, row, "server_group_id", "resource_id")

    # Listener
    for row in bucket["listeners"]:
        alias = plantuml_alias("LIS", row.get("listener_id", row.get("load_balancer_id", "")))
        label_parts = [row.get("service_code", "").upper() + " Listener"]
        protocol = row.get("protocol", "")
        port = row.get("port", "")
        if protocol or port:
            label_parts.append("/".join(part for part in (protocol, port) if part))
        add_root_node(alias, "listener", plantuml_label(*label_parts))
        register_resource_node(alias, row, "listener_id", "resource_id")
        parent_alias = resource_nodes.get(row.get("load_balancer_id", ""), "")
        if parent_alias:
            add_edge(parent_alias, alias, "监听")
        for server_group_id in split_ids(row.get("server_group_ids", "")):
            target_alias = resource_nodes.get(server_group_id, "")
            if target_alias:
                add_edge(alias, target_alias, "转发")

    # Backend Server
    for row in bucket["server_group_servers"]:
        group_alias = resource_nodes.get(row.get("server_group_id", ""), "")
        if not group_alias:
            continue
        target_alias = resource_nodes.get(row.get("server_id", ""), "")
        if target_alias:
            add_edge(group_alias, target_alias, "后端", dashed=True)
            continue
        alias = plantuml_alias("BACKEND", row.get("server_id", row.get("resource_id", "")))
        label_parts = ["Backend", row.get("server_id", "") or row.get("resource_id", "")]
        if row.get("port"):
            label_parts.append(f"端口: {row['port']}")
        add_root_node(alias, "backend", plantuml_label(*label_parts))
        register_resource_node(alias, row, "server_id", "resource_id")
        add_edge(group_alias, alias, "后端", dashed=True)

    # EIP
    for row in bucket["eips"]:
        alias = plantuml_alias("EIP", row.get("allocation_id", ""))
        label_parts = ["EIP", row.get("ip_address", ""), row.get("allocation_id", "")]
        if row.get("status"):
            label_parts.append(f"状态: {row['status']}")
        add_root_node(alias, "eip", plantuml_label(*label_parts))
        register_resource_node(alias, row, "allocation_id", "resource_id")
        for key in ("instance_id", "associated_instance_id", "bind_resource_id"):
            target_alias = resource_nodes.get(row.get(key, ""), "")
            if target_alias:
                add_edge(alias, target_alias, "绑定")
                break

    # VPN Connection
    for row in bucket["vpn_connections"]:
        alias = plantuml_alias("VPN_CONN", row.get("vpn_connection_id", ""))
        label_parts = [
            "VPN Connection",
            resource_display_name(row, ("resource_name",), ("vpn_connection_id", "resource_id")),
            row.get("vpn_connection_id", ""),
        ]
        add_root_node(alias, "vpn_connection", plantuml_label(*label_parts))
        register_resource_node(alias, row, "vpn_connection_id", "resource_id")
        parent_alias = resource_nodes.get(row.get("vpn_gateway_id", ""), "")
        if parent_alias:
            add_edge(parent_alias, alias, dashed=True)

    # SSL-VPN
    for row in bucket["ssl_vpn_servers"]:
        alias = plantuml_alias("SSL_VPN", row.get("ssl_vpn_server_id", ""))
        label_parts = [
            "SSL-VPN",
            resource_display_name(row, ("resource_name",), ("ssl_vpn_server_id", "resource_id")),
            row.get("ssl_vpn_server_id", ""),
        ]
        if row.get("internet_ip"):
            label_parts.append(f"公网: {row['internet_ip']}")
        add_root_node(alias, "ssl_vpn", plantuml_label(*label_parts))
        register_resource_node(alias, row, "ssl_vpn_server_id", "resource_id")
        parent_alias = resource_nodes.get(row.get("vpn_gateway_id", ""), "")
        if parent_alias:
            add_edge(parent_alias, alias, dashed=True)

    # 未连接到任何其他节点的根级资源，连到 VPC
    for alias in root_nodes:
        if alias != vpc_alias and alias not in connected:
            add_edge(vpc_alias, alias)

    # 构建 PlantUML 代码（扁平布局，不使用嵌套块）
    puml_lines = ["@startuml"]
    puml_lines.append("' 全局样式")
    puml_lines.append("skinparam handwritten false")
    puml_lines.append("skinparam RectangleBackgroundColor #F5F5F5")
    puml_lines.append("skinparam RectangleBorderColor #666666")
    puml_lines.append("skinparam NodeBackgroundColor #E3F2FD")
    puml_lines.append("skinparam NodeBorderColor #1E88E5")
    puml_lines.append("skinparam DatabaseBackgroundColor #FFF3E0")
    puml_lines.append("skinparam DatabaseBorderColor #E65100")
    puml_lines.append("left to right direction")
    puml_lines.append("")

    # VPC 根节点
    puml_lines.append(root_nodes[vpc_alias])

    # VSwitch 及其内部节点
    for vswitch_id in sorted(vswitch_groups, key=lambda item: (vswitch_groups[item]["label"], item)):
        group = vswitch_groups[vswitch_id]
        puml_lines.append(_plantuml_node_def(group["anchor_alias"], "vswitch", group["label"]))
        for node_alias, node_def in group["nodes"].items():
            puml_lines.append(node_def)

    # 根级节点（排除 VPC 本身）
    for alias, node_def in root_nodes.items():
        if alias != vpc_alias:
            puml_lines.append(node_def)

    # 连线
    for edge_line in edges:
        puml_lines.append(edge_line)

    puml_lines.append("@enduml")

    # 包装为 Markdown
    md_lines = [
        f"# {title}",
        "",
        "- 说明：仅根据显式字段和确定性映射生成资源关系拓扑，不表示真实访问路径。",
        "- 渲染：将 PlantUML 代码块复制到 [PlantUML Online Server](https://www.plantuml.com/plantuml/uml) 或使用 IDE 插件渲染。",
    ]
    if events:
        md_lines.extend(
            [
                "",
                "> 检测到部分关系缺失，相关接口失败如下：",
                *[
                    f"> - {row.get('service', '')} / {row.get('api', '')} / {row.get('message', '')}"
                    for row in events
                ],
            ]
        )
    md_lines.extend(["", "```plantuml", *puml_lines, "```", ""])
    return "\n".join(md_lines).rstrip() + "\n"

def build_topology_plantuml_documents(
    raw_rows: list[dict[str, str]],
    details: DetailedAssets,
) -> dict[str, str]:
    """调用共享归类层，为每个 VPC 桶生成 PlantUML 嵌入 Markdown 的拓扑文档。"""
    buckets = collect_topology_buckets(raw_rows, details)
    docs: dict[str, str] = {}
    topology_entries: list[tuple[str, str, str]] = []

    for vpc_id, bucket in sorted(
        buckets.groups.items(),
        key=lambda item: (item[1].get("vpc", {}).get("region_id", ""), item[0]),
    ):
        vpc_row = bucket.get("vpc", {})
        region_id = vpc_row.get("region_id", "")
        vpc_name = resource_display_name(vpc_row, ("resource_name",), ("resource_id",)) if vpc_row else vpc_id
        title = f"{region_id or 'unknown'} / {vpc_name} / {vpc_id}"
        filename = f"{safe_dirname(region_id or 'unknown')}__{safe_dirname(vpc_id)}.md"
        events = topology_collection_events(details, region_id=region_id, resource_ids=bucket["resource_ids"])
        docs[filename] = render_bucket_plantuml(
            f"网络拓扑：{title}",
            plantuml_label("VPC", vpc_name, vpc_id),
            vpc_id,
            bucket,
            events,
        )
        topology_entries.append((filename, title, str(len(bucket["resource_ids"]))))

    unassigned_events = topology_collection_events(details, resource_ids=buckets.unassigned["resource_ids"])
    docs["unassigned.md"] = render_bucket_plantuml(
        "网络拓扑：未归属资源",
        plantuml_label("未归属 VPC 的资源", buckets.subscription),
        "unassigned",
        buckets.unassigned,
        unassigned_events,
    )

    readme_lines = [
        "# 网络拓扑文件",
        "",
        "- 说明：每个 `VPC` 单独输出一份 `PlantUML` 拓扑图，只展示显式字段和确定性映射能确认的关系。",
        "- 边界：不按名称、同地域或同标签猜测依赖关系；未能确认 `VPC` 归属的资源会写入 `unassigned.md`。",
        "- 渲染：将 PlantUML 代码块复制到 [PlantUML Online Server](https://www.plantuml.com/plantuml/uml) 或使用 IDE 插件渲染。",
        "",
        "## 文件列表",
    ]
    if topology_entries:
        readme_lines.extend(
            f"- [{filename}](./{filename})：{title}，资源ID数={count}"
            for filename, title, count in topology_entries
        )
    else:
        readme_lines.append("- 当前未识别到 VPC 资源。")
    readme_lines.append(
        f"- [unassigned.md](./unassigned.md)：未能确认 VPC 归属的资源，资源ID数={len(buckets.unassigned['resource_ids'])}"
    )
    readme_lines.append("")
    docs["README.md"] = "\n".join(readme_lines)
    return docs


def write_topology_documents(path: Path, documents: dict[str, str]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for filename, content in documents.items():
        write_text(path / filename, content)



def build_report_sheets(
    raw_rows: list[dict[str, str]],
    details: DetailedAssets,
    findings: list[Any] | None = None,
    generated_at: str = "",
) -> list[Sheet]:
    network_services = {
        "vpc",
        "slb",
        "alb",
        "nlb",
        "cen",
        "ga",
        "cdn",
        "dcdn",
        "alidns",
        "pvtz",
    }
    database_services = {"rds", "polardb", "kvstore", "dds", "adb", "hbase"}
    storage_services = {"oss", "nas", "ebs"}
    container_services = {"cs", "cr", "eci"}
    security_services = {
        "cms",
        "arms",
        "log",
        "kms",
        "yundun-sas",
        "yundun-cloudfirewall",
        "yundun-waf",
        "yundun-bastionhost",
        "pam",
    }

    ecs_snapshot_rows = filter_by_resource_type(raw_rows, {"ACS::ECS::Snapshot"})
    sheets = [
        Sheet("报告说明", REPORT_INFO_COLUMNS, build_report_info_rows(raw_rows, details, generated_at)),
        Sheet("总览统计", SUMMARY_COLUMNS, build_summary_rows(raw_rows)),
        Sheet("采集问题", COLLECTION_EVENT_COLUMNS, collection_event_rows(details)),
    ]
    if findings is not None:
        split_rows = split_finding_rows(findings)
        sheets.extend(
            [
                Sheet("巡检总览", FINDING_SUMMARY_COLUMNS, finding_summary_rows(findings)),
                Sheet("巡检明细", FINDING_COLUMNS, finding_rows(findings)),
                Sheet("闲置资源", FINDING_COLUMNS, split_rows["idle"]),
                Sheet("未使用配置", FINDING_COLUMNS, split_rows["unused_config"]),
                Sheet("高风险暴露", FINDING_COLUMNS, split_rows["exposure"]),
                Sheet("指标疑似闲置", FINDING_COLUMNS, split_rows["suspected_idle"]),
            ]
        )

    sheets.extend(
        [
            Sheet("ECS云服务器", ECS_INSTANCE_COLUMNS, details.ecs_instances),
            Sheet("ECS磁盘", ECS_DISK_COLUMNS, details.ecs_disks),
            Sheet("ECS安全组", ECS_SECURITY_GROUP_COLUMNS, details.ecs_security_groups),
            Sheet("ECS快照", RAW_RESOURCE_COLUMNS, ecs_snapshot_rows),
            Sheet("网络与负载均衡", RAW_RESOURCE_COLUMNS, filter_by_service(raw_rows, network_services)),
            Sheet("数据库", RAW_RESOURCE_COLUMNS, filter_by_service(raw_rows, database_services)),
            Sheet("存储", RAW_RESOURCE_COLUMNS, filter_by_service(raw_rows, storage_services)),
            Sheet("容器", RAW_RESOURCE_COLUMNS, filter_by_service(raw_rows, container_services)),
            Sheet("漏洞修复命令", SAS_VULNERABILITY_COLUMNS, details.sas_vulnerabilities),
            Sheet("安全监控", RAW_RESOURCE_COLUMNS, filter_by_service(raw_rows, security_services)),
            Sheet("全部资源", RAW_RESOURCE_COLUMNS, raw_rows),
        ]
    )
    return sheets


def looks_access_denied(error: AliyunCliError) -> bool:
    text = f"{error.stdout}\n{error.stderr}".lower()
    denied_markers = (
        "accessdenied",
        "access denied",
        "forbidden",
        "no permission",
        "not authorized",
        "unauthorized",
        "denied",
        "无权",
        "没有权限",
        "权限",
    )
    return any(marker in text for marker in denied_markers)


def verify_permissions(args: argparse.Namespace, subscription: Subscription) -> int:
    failed = 0
    print(f"[权限验证] 开始 订阅={subscription.label}")
    for check in VERIFY_CHECKS:
        error_detail = ""
        try:
            run_aliyun(
                check["args"],
                profile=subscription.profile,
                region=args.region,
                timeout=args.timeout,
            )
            allowed = True
            denied = False
        except AliyunCliError as exc:
            allowed = False
            denied = looks_access_denied(exc)
            error_detail = str(exc)
        except subprocess.TimeoutExpired as exc:
            allowed = False
            denied = False
            error_detail = f"执行超时，命令在 {exc.timeout} 秒内未返回"

        expect = check["expect"]
        ok = (expect == "allow" and allowed) or (expect == "deny" and denied)
        status = "通过" if ok else "失败"
        if not ok:
            failed += 1
        expected_text = "允许" if expect == "allow" else "拒绝"
        detail_suffix = f" 原因={error_detail}" if error_detail and not ok else ""
        print(
            f"[权限验证] {status} 订阅={subscription.label} "
            f"预期={expected_text} 检查项={check['name']}{detail_suffix}"
        )

    return failed


def default_output_dir() -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return PROJECT_ROOT / "outputs" / f"aliyun-assets-{stamp}"


def project_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def safe_dirname(value: str) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\s]+', "_", value.strip())
    return cleaned.strip("._-") or "subscription"


def parse_subscription_spec(spec: str) -> Subscription:
    parts = [part.strip() for part in spec.split(",", 2)]
    profile = parts[0] if parts else ""
    if not profile:
        raise ValueError("订阅 profile 不能为空")

    label = parts[1] if len(parts) >= 2 and parts[1] else profile
    scope = parts[2] if len(parts) >= 3 else ""
    return Subscription(profile=profile, label=label, multi_account_scope=scope)


def read_subscriptions_file(path: Path) -> list[Subscription]:
    subscriptions: list[Subscription] = []
    with path.open("r", encoding="utf-8") as fp:
        for line_no, raw_line in enumerate(fp, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                subscriptions.append(parse_subscription_spec(line))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: {exc}") from exc
    return subscriptions


def prompt_subscriptions(default_scope: str) -> list[Subscription]:
    print("请输入要梳理的 aliyun profile 名称，多个用英文逗号分隔。")
    print("不会读取或输出 AK/SK，只会把 profile 名交给 aliyun CLI 使用。")
    raw_profiles = input("profiles（多个用英文逗号分隔）: ").strip()
    profiles = [item.strip() for item in raw_profiles.split(",") if item.strip()]
    subscriptions: list[Subscription] = []

    for profile in profiles:
        label = input(f"{profile} 的输出目录名，留空则使用 profile 名: ").strip()
        scope = input(
            f"{profile} 的多账号 scope，留空则使用全局 scope 或单账号模式: "
        ).strip()
        subscriptions.append(
            Subscription(
                profile=profile,
                label=label or profile,
                multi_account_scope=scope or default_scope,
            )
        )

    return subscriptions


def collect_subscriptions(args: argparse.Namespace) -> list[Subscription]:
    subscriptions: list[Subscription] = []

    for profile in args.profile or []:
        subscriptions.append(
            Subscription(
                profile=profile,
                label=profile,
                multi_account_scope=args.multi_account_scope,
            )
        )

    if args.profiles:
        for profile in args.profiles.split(","):
            profile = profile.strip()
            if profile:
                subscriptions.append(
                    Subscription(
                        profile=profile,
                        label=profile,
                        multi_account_scope=args.multi_account_scope,
                    )
                )

    if args.subscription:
        for spec in args.subscription:
            subscription = parse_subscription_spec(spec)
            if not subscription.multi_account_scope:
                subscription = dataclasses.replace(
                    subscription,
                    multi_account_scope=args.multi_account_scope,
                )
            subscriptions.append(subscription)

    if args.subscription_file:
        for subscription in read_subscriptions_file(project_path(args.subscription_file)):
            if not subscription.multi_account_scope:
                subscription = dataclasses.replace(
                    subscription,
                    multi_account_scope=args.multi_account_scope,
                )
            subscriptions.append(subscription)

    if args.interactive or not subscriptions:
        subscriptions.extend(prompt_subscriptions(args.multi_account_scope))

    deduped: list[Subscription] = []
    seen: set[tuple[str, str, str]] = set()
    for subscription in subscriptions:
        key = (
            subscription.profile,
            subscription.label,
            subscription.multi_account_scope,
        )
        if key not in seen:
            seen.add(key)
            deduped.append(subscription)

    if not deduped:
        raise ValueError("未提供任何订阅 profile")

    return deduped


def output_path_for(
    args: argparse.Namespace,
    subscription: Subscription,
    subscriptions_count: int,
) -> Path:
    if args.output:
        if subscriptions_count > 1:
            raise ValueError("--output 只能在单订阅导出时使用")
        return project_path(args.output)

    base_dir = project_path(args.output_dir)
    return base_dir / safe_dirname(subscription.label) / "raw-resourcecenter.csv"


def report_path_for(
    args: argparse.Namespace,
    subscription: Subscription,
    subscriptions_count: int,
) -> Path:
    if args.report_output:
        if subscriptions_count > 1:
            raise ValueError("--report-output 只能在单订阅导出时使用")
        return project_path(args.report_output)

    base_dir = project_path(args.output_dir)
    return base_dir / safe_dirname(subscription.label) / "asset-report.xlsx"


def findings_path_for(
    args: argparse.Namespace,
    subscription: Subscription,
    subscriptions_count: int,
) -> Path:
    if args.findings_output:
        if subscriptions_count > 1:
            raise ValueError("--findings-output 只能在单订阅导出时使用")
        return project_path(args.findings_output)

    base_dir = project_path(args.output_dir)
    return base_dir / safe_dirname(subscription.label) / "findings.csv"


def combined_output_path(args: argparse.Namespace) -> Path:
    return project_path(args.output_dir) / "all-subscriptions.csv"


def combined_report_path(args: argparse.Namespace) -> Path:
    return project_path(args.output_dir) / "all-subscriptions-report.xlsx"


def combined_findings_path(args: argparse.Namespace) -> Path:
    return project_path(args.output_dir) / "all-subscriptions-findings.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="通过 aliyun CLI 导出阿里云资产元数据到 CSV 和 Excel 报告。",
        usage="%(prog)s [选项]",
        add_help=False,
    )
    parser._optionals.title = "可选参数"
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="显示帮助信息并退出",
    )
    parser.add_argument(
        "--profile",
        action="append",
        help="aliyun CLI profile 名称，可重复指定",
    )
    parser.add_argument(
        "--profiles",
        default="",
        help="多个 aliyun CLI profile 名称，用英文逗号分隔",
    )
    parser.add_argument(
        "--subscription",
        action="append",
        help=(
            "订阅配置，格式为 profile[,输出目录名[,多账号scope]]；"
            "可重复指定"
        ),
    )
    parser.add_argument(
        "--subscription-file",
        default="",
        help="订阅配置文件，每行一个配置：profile[,输出目录名[,scope]]",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="交互式输入 profile 名称、输出目录名和可选 scope",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="可选的 aliyun CLI 全局地域，例如 cn-shanghai",
    )
    parser.add_argument(
        "--output",
        default="",
        help="原始资源中心 CSV 输出路径；仅支持单订阅导出时使用",
    )
    parser.add_argument(
        "--report-output",
        default="",
        help="Excel 报告输出路径；仅支持单订阅导出时使用",
    )
    parser.add_argument(
        "--findings-output",
        default="",
        help="巡检发现 CSV 输出路径；仅支持单订阅导出时使用",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir()),
        help="基础输出目录；每个订阅会单独生成子目录",
    )
    parser.add_argument(
        "--no-combined",
        action="store_true",
        help="不在输出目录下生成 all-subscriptions.csv 合并文件",
    )
    parser.add_argument(
        "--no-raw-csv",
        action="store_true",
        help="不输出原始资源中心 CSV",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="不输出 Excel 报告工作簿",
    )
    topology_group = parser.add_mutually_exclusive_group()
    topology_group.add_argument(
        "--topology",
        dest="topology",
        action="store_true",
        default=True,
        help="显式开启按 VPC 输出 PlantUML 网络拓扑 Markdown 文件（默认开启）",
    )
    topology_group.add_argument(
        "--no-topology",
        dest="topology",
        action="store_false",
        help="不输出 PlantUML 网络拓扑 Markdown 文件",
    )
    parser.add_argument(
        "--no-detail",
        action="store_true",
        help="不调用 ECS 等产品详情接口，只使用资源中心原始数据生成报告",
    )
    parser.add_argument(
        "--no-checks",
        action="store_true",
        help="不执行日常运维巡检，仅导出资产清单和资产工作表",
    )
    parser.add_argument(
        "--checks-only",
        action="store_true",
        help="复用已有 raw-resourcecenter.csv，仅重新生成巡检结果和报告",
    )
    parser.add_argument(
        "--checks-config",
        default="",
        help="巡检阈值配置文件，例如 config/checks.example.json",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=("low", "medium", "high"),
        default="low",
        help="巡检报告输出的最低风险等级，默认 low",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=500,
        choices=range(1, 501),
        metavar="[1-500]",
        help="资源中心 SearchResources 的分页大小",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="导出 N 条资源后停止，适合冒烟测试",
    )
    parser.add_argument(
        "--search-expression",
        default="",
        help="可选的资源中心搜索表达式",
    )
    parser.add_argument(
        "--resource-group-id",
        default="",
        help="可选的资源组过滤条件，仅用于单账号搜索",
    )
    parser.add_argument(
        "--include-deleted",
        action="store_true",
        help="单账号搜索时包含已删除资源",
    )
    parser.add_argument(
        "--multi-account-scope",
        default="",
        help="使用 SearchMultiAccountResources，并指定资源目录、Root、资源夹或成员账号 ID 作为 scope",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="导出前执行一组允许/拒绝权限检查",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="只执行权限检查，不导出 CSV",
    )
    parser.add_argument(
        "--continue-on-verify-failure",
        action="store_true",
        help="即使 --verify 发现失败项，也继续导出",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.05,
        help="资源中心分页之间的等待秒数",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="aliyun CLI 单次命令超时时间，单位秒",
    )
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        subscriptions = collect_subscriptions(args)
        checks_config = None
        if not args.no_checks and not args.verify_only:
            checks_config = ChecksConfig.from_file(
                project_path(args.checks_config) if args.checks_config else "",
                args.severity_threshold,
            )
        if args.output and len(subscriptions) > 1:
            raise ValueError("--output 只能在单订阅导出时使用")
        if args.report_output and len(subscriptions) > 1:
            raise ValueError("--report-output 只能在单订阅导出时使用")
        if args.findings_output and len(subscriptions) > 1:
            raise ValueError("--findings-output 只能在单订阅导出时使用")
        if args.no_checks and args.checks_only:
            raise ValueError("--no-checks 和 --checks-only 不能同时使用")
        if args.topology and args.no_detail:
            raise ValueError("默认启用拓扑，--no-detail 需要配合 --no-topology 使用")
        if args.no_raw_csv and args.no_report and checks_config is None and not args.topology:
            raise ValueError("--no-raw-csv 和 --no-report 不能同时使用")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 2

    total_failed = 0
    all_rows: list[dict[str, str]] = []
    all_details = DetailedAssets()
    all_findings: list[Any] = []
    generated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S %z")

    for subscription in subscriptions:
        if args.verify or args.verify_only:
            failed = verify_permissions(args, subscription)
            total_failed += failed
            if failed:
                print(
                    f"[权限验证] 订阅={subscription.label} 失败检查项={failed}",
                    file=sys.stderr,
                )
                if args.verify and not args.verify_only and not args.continue_on_verify_failure:
                    print(
                        f"[资产梳理] 跳过订阅={subscription.label}，原因=权限验证失败",
                        file=sys.stderr,
                    )
                    continue

        if args.verify_only:
            continue

        try:
            if args.checks_only:
                raw_path = output_path_for(args, subscription, len(subscriptions))
                rows = read_raw_csv(raw_path)
                print(
                    f"[资产梳理] 复用已有底稿 订阅={subscription.label} CSV={raw_path}",
                    file=sys.stderr,
                )
            else:
                rows = search_resources(args, subscription)
            details = collect_detailed_assets(args, subscription, rows, checks_config)
            findings: list[Any] = []
            if checks_config is not None:
                context = CheckContext(
                    raw_rows=rows,
                    details=details,
                    config=checks_config,
                    now=dt.datetime.now(dt.timezone.utc),
                )
                findings = run_checks(context)
                print(
                    f"[巡检] 订阅={subscription.label} 发现项={len(findings)} "
                    f"最低风险等级={args.severity_threshold}",
                    file=sys.stderr,
                )
            if not args.no_raw_csv and not args.checks_only:
                output_path = output_path_for(args, subscription, len(subscriptions))
                write_csv(output_path, rows)
            else:
                output_path = None
            if checks_config is not None:
                findings_path = findings_path_for(args, subscription, len(subscriptions))
                write_rows_csv(findings_path, finding_rows(findings), FINDING_COLUMNS)
            else:
                findings_path = None
            if not args.no_report:
                report_path = report_path_for(args, subscription, len(subscriptions))
                write_xlsx(
                    report_path,
                    build_report_sheets(
                        rows,
                        details,
                        findings if checks_config is not None else None,
                        generated_at,
                    ),
                )
            else:
                report_path = None
            if args.topology:
                topology_path = topology_dir_for(args, subscription, len(subscriptions))
                write_topology_documents(
                    topology_path,
                    build_topology_plantuml_documents(rows, details),
                )
            else:
                topology_path = None
        except (AliyunCliError, ValueError, subprocess.TimeoutExpired) as exc:
            print(
                f"[资产梳理] 失败 订阅={subscription.label} 错误={exc}",
                file=sys.stderr,
            )
            total_failed += 1
            continue

        all_rows.extend(rows)
        extend_detail_lists(all_details, details)
        all_findings.extend(findings)
        outputs = []
        if output_path:
            outputs.append(f"CSV={output_path}")
        if findings_path:
            outputs.append(f"巡检CSV={findings_path}")
        if report_path:
            outputs.append(f"报告={report_path}")
        if topology_path:
            outputs.append(f"拓扑={topology_path}")
        print(f"[资产梳理] 已导出={len(rows)} 订阅={subscription.label} {' '.join(outputs)}")

    if not args.verify_only and len(subscriptions) > 1 and not args.no_combined:
        outputs = []
        if not args.no_raw_csv and not args.checks_only:
            combined_path = combined_output_path(args)
            write_csv(combined_path, all_rows)
            outputs.append(f"CSV={combined_path}")
        if checks_config is not None:
            combined_findings = combined_findings_path(args)
            write_rows_csv(combined_findings, finding_rows(all_findings), FINDING_COLUMNS)
            outputs.append(f"巡检CSV={combined_findings}")
        if not args.no_report:
            combined_xlsx = combined_report_path(args)
            write_xlsx(
                combined_xlsx,
                build_report_sheets(
                    all_rows,
                    all_details,
                    all_findings if checks_config is not None else None,
                    generated_at,
                ),
            )
            outputs.append(f"报告={combined_xlsx}")
        print(f"[资产梳理] 合并导出={len(all_rows)} {' '.join(outputs)}")

    return 2 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
