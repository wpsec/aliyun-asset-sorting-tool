"""巡检结果汇总和 Excel 输出列。"""

from __future__ import annotations

from .models import CheckFinding, SEVERITY_ORDER


FINDING_COLUMNS = [
    ("subscription", "订阅"),
    ("account_id", "账号ID"),
    ("region_id", "地域"),
    ("service", "云服务"),
    ("resource_type", "资源类型"),
    ("resource_id", "资源ID"),
    ("resource_name", "资源名称"),
    ("severity", "风险等级"),
    ("remediation_priority", "整改优先级"),
    ("billing_attribute", "计费属性"),
    ("billing_note", "计费说明"),
    ("check_id", "检查项ID"),
    ("check_name", "检查项名称"),
    ("category", "分类"),
    ("finding", "发现结果"),
    ("recommendation", "建议动作"),
    ("evidence", "证据"),
]

FINDING_SUMMARY_COLUMNS = [
    ("subscription", "订阅"),
    ("service", "云服务"),
    ("severity", "风险等级"),
    ("category", "分类"),
    ("count", "问题数量"),
]


def finding_rows(findings: list[CheckFinding]) -> list[dict[str, str]]:
    rows = [finding.to_row() for finding in findings]
    return sorted(
        rows,
        key=lambda row: (
            row.get("subscription", ""),
            row.get("remediation_priority", ""),
            -SEVERITY_ORDER.get(row.get("severity_code", "low"), 1),
            row.get("service", ""),
            row.get("check_id", ""),
            row.get("resource_id", ""),
        ),
    )


def finding_summary_rows(findings: list[CheckFinding]) -> list[dict[str, str]]:
    counts: dict[tuple[str, str, str, str], int] = {}
    for item in findings:
        row = item.to_row()
        key = (
            row["subscription"],
            row["service"],
            row["severity"],
            row["category"],
        )
        counts[key] = counts.get(key, 0) + 1

    return [
        {
            "subscription": subscription,
            "service": service,
            "severity": severity,
            "category": category,
            "count": str(count),
        }
        for (subscription, service, severity, category), count in sorted(counts.items())
    ]


def split_finding_rows(findings: list[CheckFinding]) -> dict[str, list[dict[str, str]]]:
    rows = finding_rows(findings)
    return {
        "idle": [row for row in rows if row.get("category") == "闲置资源"],
        "unused_config": [row for row in rows if row.get("category") == "未使用配置"],
        "exposure": [row for row in rows if row.get("category") == "高风险暴露"],
        "suspected_idle": [row for row in rows if row.get("category") == "疑似闲置"],
    }
