"""VPC 和公网网络资产巡检规则。"""

from __future__ import annotations

from .helpers import evidence_from_pairs, finding, rows_by_type
from .models import CheckContext, CheckFinding


VPC_TYPES = {"ACS::VPC::VPC"}
VSWITCH_TYPES = {"ACS::VPC::VSwitch"}


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_empty_vpcs(context))
    findings.extend(check_empty_vswitches(context))
    findings.extend(check_unused_eips(context))
    findings.extend(check_nat_without_rules(context))
    findings.extend(check_vpn_without_connection(context))
    return findings


def check_empty_vpcs(context: CheckContext) -> list[CheckFinding]:
    check_id = "vpc_empty_vpc"
    if not context.config.is_enabled(check_id):
        return []

    used_vpcs = {
        row.get("vpc_id", "")
        for row in context.details.ecs_instances + context.details.ecs_network_interfaces
        if row.get("vpc_id")
    }

    findings = []
    for row in rows_by_type(context.raw_rows, VPC_TYPES):
        if row.get("resource_id") in used_vpcs:
            continue
        findings.append(
            finding(
                row,
                service="vpc（专有网络）",
                resource_type="专有网络",
                severity="low",
                check_id=check_id,
                check_name="VPC 未发现 ECS/ENI 直接使用",
                category="闲置资源",
                message="VPC 未发现 ECS 实例或弹性网卡直接绑定，不代表未被托管服务、私网接入或预留网络使用。",
                recommendation="结合控制台、标签、负责人和托管服务依赖复核；确认无使用计划后再评估清理。",
                evidence=evidence_from_pairs(资源类型=row.get("resource_type"), 创建时间=row.get("create_time")),
            )
        )
    return findings


def check_empty_vswitches(context: CheckContext) -> list[CheckFinding]:
    check_id = "vpc_empty_vswitch"
    if not context.config.is_enabled(check_id):
        return []

    used_vswitches = {
        row.get("vswitch_id", "")
        for row in context.details.ecs_instances + context.details.ecs_network_interfaces
        if row.get("vswitch_id")
    }

    findings = []
    for row in rows_by_type(context.raw_rows, VSWITCH_TYPES):
        if row.get("resource_id") in used_vswitches:
            continue
        findings.append(
            finding(
                row,
                service="vpc（专有网络）",
                resource_type="交换机",
                severity="low",
                check_id=check_id,
                check_name="交换机未发现 ECS/ENI 直接使用",
                category="闲置资源",
                message="交换机未发现 ECS 实例或弹性网卡直接绑定，不代表未被云数据库、容器、托管服务或预留子网使用。",
                recommendation="结合控制台可用 IP、标签、资源组和业务用途复核；确认无使用计划后再按变更流程清理。",
                evidence=evidence_from_pairs(可用区=row.get("zone_id"), 创建时间=row.get("create_time")),
            )
        )
    return findings


def check_unused_eips(context: CheckContext) -> list[CheckFinding]:
    check_id = "vpc_unused_eip"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for eip in context.details.vpc_eips:
        status = eip.get("status", "").lower()
        bound_id = eip.get("instance_id") or eip.get("associated_instance_id") or eip.get("bind_resource_id")
        if bound_id or status in {"inuse", "binded", "associated"}:
            continue
        findings.append(
            finding(
                eip,
                service="eip（弹性公网IP）",
                resource_type="弹性公网IP",
                severity="medium",
                check_id=check_id,
                check_name="未绑定 EIP",
                category="闲置资源",
                message="EIP 当前未绑定云资源。",
                recommendation="确认是否为预留公网 IP；长期未绑定的 EIP 建议评估释放以减少成本和暴露面。",
                evidence=evidence_from_pairs(IP=eip.get("ip_address"), 状态=eip.get("status"), 付费类型=eip.get("charge_type")),
            )
        )
    return findings


def check_nat_without_rules(context: CheckContext) -> list[CheckFinding]:
    check_id = "vpc_nat_without_rules"
    if not context.config.is_enabled(check_id):
        return []

    nat_ids_with_rules = {
        row.get("nat_gateway_id", "")
        for row in context.details.vpc_snat_entries + context.details.vpc_dnat_entries
        if row.get("nat_gateway_id")
    }

    findings = []
    for nat in context.details.vpc_nat_gateways:
        nat_id = nat.get("nat_gateway_id", "")
        if not nat_id or nat_id in nat_ids_with_rules:
            continue
        findings.append(
            finding(
                nat,
                service="nat（NAT网关）",
                resource_type="NAT网关",
                severity="low",
                check_id=check_id,
                check_name="NAT 网关无 SNAT/DNAT 规则",
                category="闲置资源",
                message="NAT 网关未发现 SNAT 或 DNAT 规则。",
                recommendation="确认是否仍承载业务；无使用计划的 NAT 网关建议评估释放。",
                evidence=evidence_from_pairs(VPC=nat.get("vpc_id"), 状态=nat.get("status"), 规格=nat.get("spec")),
            )
        )
    return findings


def check_vpn_without_connection(context: CheckContext) -> list[CheckFinding]:
    check_id = "vpc_vpn_without_connection"
    if not context.config.is_enabled(check_id):
        return []

    vpn_ids_with_connections = {
        row.get("vpn_gateway_id", "")
        for row in context.details.vpc_vpn_connections
        if row.get("vpn_gateway_id")
    }
    vpn_ids_with_ssl_servers = {
        row.get("vpn_gateway_id", "")
        for row in context.details.vpc_ssl_vpn_servers
        if row.get("vpn_gateway_id")
    }
    ssl_query_failed_regions = {
        row.get("region_id", "")
        for row in context.details.collection_events
        if row.get("service") == "vpn"
        and row.get("api") == "DescribeSslVpnServers"
        and row.get("status") == "query_failed"
    }

    findings = []
    for gateway in context.details.vpc_vpn_gateways:
        gateway_id = gateway.get("vpn_gateway_id", "")
        if not gateway_id:
            continue
        if gateway.get("region_id", "") in ssl_query_failed_regions:
            continue
        if gateway_id in vpn_ids_with_connections or gateway_id in vpn_ids_with_ssl_servers:
            continue
        findings.append(
            finding(
                gateway,
                service="vpn（VPN）",
                resource_type="VPN网关",
                severity="low",
                check_id=check_id,
                check_name="VPN 网关无 IPsec/SSL 配置",
                category="闲置资源",
                message="VPN 网关未发现 IPsec 连接或 SSL-VPN 服务端配置。",
                recommendation="确认是否为预留网关；无 IPsec/SSL 使用计划的 VPN 网关建议评估释放。",
                evidence=evidence_from_pairs(VPC=gateway.get("vpc_id"), 状态=gateway.get("status"), 创建时间=gateway.get("create_time")),
            )
        )
    return findings
