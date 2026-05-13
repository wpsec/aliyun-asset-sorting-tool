"""巡检规则调度器。"""

from __future__ import annotations

from . import database, ecs, metrics, oss, ram, slb, vpc
from .models import CheckContext, CheckFinding


def run_checks(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    for module in (ecs, vpc, slb, ram, oss, database, metrics):
        findings.extend(module.run(context))
    return [
        item
        for item in findings
        if context.config.allows_severity(item.severity)
        and not context.config.is_whitelisted(item)
    ]
