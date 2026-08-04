from dojo.models import Finding


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def map_severity(value):
    value = clean(value).lower()

    if value == "critical":
        return "Critical"
    if value == "high":
        return "High"
    if value == "medium":
        return "Medium"
    if value == "low":
        return "Low"
    if value == "info":
        return "Info"

    return "Info"


finding = Finding(
    title=clean(row.get("Devoteam Findings")),
    test=test,
    severity=map_severity(row.get("Risk According to Devoteam")),
    cvssv3=clean(row.get("CVSS according to Devoteam")),
    description=f"""
Asset: {clean(row.get("Asset"))}
Vulnerability Type: {clean(row.get("Vulnerability Type"))}
Remediation Owner: {clean(row.get("SES Remediation Owner"))}
Target Closure Date: {clean(row.get("Target Closure Date (DD.MM.YYYY)"))}
Evidence for Closure: {clean(row.get("Justification / Evidence for Closure"))}
Additional Comments: {clean(row.get("SES Additional Comments and Notes"))}
""".strip(),
    impact=clean(row.get("Contextual Comments on Impact")),
    mitigation=f"""
Recommendation Description:
{clean(row.get("Devoteam recommendations Description"))}

Remediation Plan:
{clean(row.get("Remediation Plan"))}
""".strip(),
    active=True,
    verified=False,
    static_finding=False,
    dynamic_finding=True,
    unique_id_from_tool=clean(row.get("Vulnerability ID")),
)