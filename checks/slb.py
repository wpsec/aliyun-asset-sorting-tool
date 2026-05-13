"""负载均衡巡检规则。"""

from __future__ import annotations

from .helpers import evidence_from_pairs, finding
from .models import CheckContext, CheckFinding


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_load_balancers_without_listener(context))
    findings.extend(check_server_groups_without_backend(context))
    findings.extend(check_public_load_balancers_without_https(context))
    return findings


def check_load_balancers_without_listener(context: CheckContext) -> list[CheckFinding]:
    check_id = "slb_without_listener"
    if not context.config.is_enabled(check_id):
        return []

    listener_lbs = {
        row.get("load_balancer_id", "")
        for row in (
            context.details.slb_listeners
            + context.details.alb_listeners
            + context.details.nlb_listeners
        )
        if row.get("load_balancer_id")
    }

    findings = []
    for row in context.details.slb_load_balancers:
        findings.extend(_lb_without_listener(row, listener_lbs, "slb（传统型负载均衡）"))
    for row in context.details.alb_load_balancers:
        findings.extend(_lb_without_listener(row, listener_lbs, "alb（应用型负载均衡）"))
    for row in context.details.nlb_load_balancers:
        findings.extend(_lb_without_listener(row, listener_lbs, "nlb（网络型负载均衡）"))
    return findings


def _lb_without_listener(
    row: dict[str, str],
    listener_lbs: set[str],
    service: str,
) -> list[CheckFinding]:
    lb_id = row.get("load_balancer_id", "")
    if not lb_id or lb_id in listener_lbs:
        return []
    return [
        finding(
            row,
            service=service,
            resource_type="负载均衡",
            severity="medium",
            check_id="slb_without_listener",
            check_name="负载均衡无监听",
            category="闲置资源",
            message="负载均衡实例未发现监听。",
            recommendation="确认是否为预留实例；无监听且无使用计划的负载均衡建议评估释放。",
            evidence=evidence_from_pairs(地址=row.get("address"), 状态=row.get("status"), VPC=row.get("vpc_id")),
        )
    ]


def check_public_load_balancers_without_https(context: CheckContext) -> list[CheckFinding]:
    check_id = "slb_public_without_https"
    if not context.config.is_enabled(check_id):
        return []

    listeners_by_lb: dict[str, list[dict[str, str]]] = {}
    for listener in context.details.slb_listeners + context.details.alb_listeners + context.details.nlb_listeners:
        lb_id = listener.get("load_balancer_id", "")
        if lb_id:
            listeners_by_lb.setdefault(lb_id, []).append(listener)

    findings: list[CheckFinding] = []
    for row, service in load_balancers_with_service(context):
        lb_id = row.get("load_balancer_id", "")
        if not lb_id or not is_public_load_balancer(row):
            continue
        listeners = listeners_by_lb.get(lb_id, [])
        if not listeners or any(listener.get("status") == "query_failed" for listener in listeners):
            continue
        protocols = {listener.get("protocol", "").lower() for listener in listeners}
        if protocols & {"https", "tls", "ssl"}:
            continue
        findings.append(
            finding(
                row,
                service=service,
                resource_type="负载均衡",
                severity="low",
                check_id=check_id,
                check_name="公网负载均衡未发现 HTTPS/TLS 监听",
                category="高风险暴露",
                message="公网负载均衡存在监听，但未发现 HTTPS/TLS 类型监听。",
                recommendation="确认是否承载 HTTP 明文业务；对公网业务建议启用 HTTPS/TLS 或在上游网关完成加密。",
                evidence=evidence_from_pairs(
                    地址=row.get("address"),
                    地址类型=row.get("address_type"),
                    监听协议=",".join(sorted(protocols)),
                ),
            )
        )
    return findings


def load_balancers_with_service(context: CheckContext) -> list[tuple[dict[str, str], str]]:
    return (
        [(row, "slb（传统型负载均衡）") for row in context.details.slb_load_balancers]
        + [(row, "alb（应用型负载均衡）") for row in context.details.alb_load_balancers]
        + [(row, "nlb（网络型负载均衡）") for row in context.details.nlb_load_balancers]
    )


def is_public_load_balancer(row: dict[str, str]) -> bool:
    text = " ".join(str(row.get(key, "")).lower() for key in ("address_type", "address"))
    return any(marker in text for marker in ("internet", "public", "公网"))


def check_server_groups_without_backend(context: CheckContext) -> list[CheckFinding]:
    check_id = "slb_server_group_without_backend"
    if not context.config.is_enabled(check_id):
        return []

    server_groups_with_servers = {
        row.get("server_group_id", "")
        for row in context.details.alb_server_group_servers + context.details.nlb_server_group_servers
        if row.get("server_group_id")
    }

    findings = []
    for row in context.details.alb_server_groups:
        findings.extend(_server_group_without_backend(row, server_groups_with_servers, "alb（应用型负载均衡）"))
    for row in context.details.nlb_server_groups:
        findings.extend(_server_group_without_backend(row, server_groups_with_servers, "nlb（网络型负载均衡）"))
    return findings


def _server_group_without_backend(
    row: dict[str, str],
    server_groups_with_servers: set[str],
    service: str,
) -> list[CheckFinding]:
    group_id = row.get("server_group_id", "")
    if not group_id or group_id in server_groups_with_servers:
        return []
    return [
        finding(
            row,
            service=service,
            resource_type="服务器组",
            severity="medium",
            check_id="slb_server_group_without_backend",
            check_name="服务器组无后端服务器",
            category="闲置资源",
            message="服务器组未发现后端服务器。",
            recommendation="确认是否为预留服务器组；无后端且无引用计划的服务器组建议按变更流程清理。",
            evidence=evidence_from_pairs(VPC=row.get("vpc_id"), 协议=row.get("protocol"), 类型=row.get("server_group_type")),
        )
    ]
