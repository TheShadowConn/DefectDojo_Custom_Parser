import json
import hashlib
from dojo.models import Finding


class CustomJsonParser:
    def get_scan_types(self):
        return ["Custom JSON Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Custom JSON Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Parser for custom JSON vulnerability reports."

    def get_findings(self, filename, test):
        findings = []

        data = json.load(filename)

        # Supports both formats:
        # 1. {"vulnerabilities": [ ... ]}
        # 2. [ ... ]
        if isinstance(data, dict):
            items = (
                data.get("vulnerabilities")
                or data.get("findings")
                or data.get("results")
                or []
            )
        elif isinstance(data, list):
            items = data
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue

            asset = self.clean(self.get_value(item, ["Asset", "asset"]))
            vulnerability_type = self.clean(
                self.get_value(item, ["Vulnerability type", "Vulnerability Type", "vulnerability_type"])
            )
            finding_name = self.clean(
                self.get_value(item, ["Finding name", "Finding Name", "Devoteam Findings", "title", "name"])
            )
            cvss = self.clean(
                self.get_value(item, ["CVSS", "CVSS according to Devoteam", "cvss", "cvssv3"])
            )
            risk = self.clean(
                self.get_value(item, ["Risk", "Risk According to Devoteam", "Risk According to SES", "severity"])
            )
            recommendation_description = self.clean(
                self.get_value(
                    item,
                    [
                        "Recommendation description",
                        "Recommendation Description",
                        "Devoteam recommendations Description",
                        "recommendation_description",
                    ],
                )
            )
            impact = self.clean(
                self.get_value(item, ["Impact", "Contextual Comments on Impact", "impact"])
            )
            remediation_plan = self.clean(
                self.get_value(item, ["Remediation plan", "Remediation Plan", "remediation_plan"])
            )
            remediation_owner = self.clean(
                self.get_value(item, ["Remediation owner", "Remediation Owner", "remediation_owner"])
            )
            target_closure_date = self.clean(
                self.get_value(
                    item,
                    [
                        "Target closure date",
                        "Target Closure Date",
                        "Target Closure Date (DD.MM.YYYY)",
                        "target_closure_date",
                    ],
                )
            )
            evidence_for_closure = self.clean(
                self.get_value(
                    item,
                    [
                        "Evidence for closure",
                        "Evidence for Closure",
                        "Justification / Evidence for Closure",
                        "evidence_for_closure",
                    ],
                )
            )
            additional_comments = self.clean(
                self.get_value(
                    item,
                    [
                        "Additional comments",
                        "Additional Comments",
                        "Additional Comments and Notes",
                        "SES Additional Comments and Notes",
                        "additional_comments",
                    ],
                )
            )

            if not finding_name:
                finding_name = "Untitled Finding"

            severity = self.map_severity(risk)

            description = f"""
Asset: {asset}
Vulnerability Type: {vulnerability_type}
Remediation Owner: {remediation_owner}
Target Closure Date: {target_closure_date}
Evidence for Closure: {evidence_for_closure}
Additional Comments: {additional_comments}
""".strip()

            mitigation = f"""
Recommendation Description:
{recommendation_description}

Remediation Plan:
{remediation_plan}
""".strip()

            unique_id = self.generate_unique_id(
                asset,
                vulnerability_type,
                finding_name,
                cvss,
                risk,
            )

            finding = Finding(
                title=finding_name,
                test=test,
                severity=severity,
                description=description,
                impact=impact,
                mitigation=mitigation,
                cvssv3=cvss,
                active=True,
                verified=False,
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=unique_id,
            )

            findings.append(finding)

        return findings

    def get_value(self, item, possible_keys):
        for key in possible_keys:
            if key in item:
                return item.get(key)
        return ""

    def clean(self, value):
        if value is None:
            return ""
        return str(value).strip()

    def map_severity(self, value):
        value = self.clean(value).lower()

        if value == "critical":
            return "Critical"
        if value == "high":
            return "High"
        if value == "medium":
            return "Medium"
        if value == "low":
            return "Low"
        if value in ["info", "informational"]:
            return "Info"

        return "Info"

    def generate_unique_id(self, asset, vulnerability_type, finding_name, cvss, risk):
        raw_value = f"{asset}|{vulnerability_type}|{finding_name}|{cvss}|{risk}"
        return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
