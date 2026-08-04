import json
import hashlib
from dojo.models import Finding


class DevoteamScanResultParserParser:
    def get_scan_types(self):
        return ["Devoteam Scan Result Parser"]

    def get_label_for_scan_types(self, scan_type):
        return "Devoteam Scan Result Parser"

    def get_description_for_scan_types(self, scan_type):
        return "Parser for Devoteam pentest validation scan result JSON files."

    def get_findings(self, filename, test):
        findings = []

        data = json.load(filename)

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

            asset = self.clean(item.get("Asset"))
            vulnerability_id = self.clean(item.get("Vulnerability ID"))
            status = self.clean(item.get("Status"))
            vulnerability_type = self.clean(item.get("Vulnerability Type"))
            finding_name = self.clean(item.get("Devoteam Findings"))
            cvss = self.clean(item.get("CVSS according to Devoteam"))
            risk_devoteam = self.clean(item.get("Risk According to Devoteam"))
            risk_ses = self.clean(item.get("Risk According to SES"))
            recommendation_description = self.clean(
                item.get("Devoteam recommendations Description")
            )
            recommendation_type_detail = self.clean(
                item.get("Recommendation Type Detail")
            )
            remediation_owner = self.clean(item.get("SES Remediation Owner"))
            target_closure_date = self.clean(
                item.get("Target Closure Date (DD.MM.YYYY)")
            )
            evidence_for_closure = self.clean(
                item.get("Justification / Evidence for Closure")
            )
            cleaning_steps = self.clean(item.get("SES Cleaning Steps"))
            additional_comments = self.clean(
                item.get("SES Additional Comments and Notes")
            )

            if not finding_name:
                finding_name = vulnerability_id or "Untitled Devoteam Finding"

            severity = self.map_severity(risk_ses or risk_devoteam)

            description = self.build_description(
                asset=asset,
                vulnerability_id=vulnerability_id,
                status=status,
                vulnerability_type=vulnerability_type,
                risk_devoteam=risk_devoteam,
                risk_ses=risk_ses,
                remediation_owner=remediation_owner,
                target_closure_date=target_closure_date,
                evidence_for_closure=evidence_for_closure,
                cleaning_steps=cleaning_steps,
                additional_comments=additional_comments,
            )

            mitigation = self.build_mitigation(
                recommendation_description=recommendation_description,
                recommendation_type_detail=recommendation_type_detail,
            )

            unique_id = self.generate_unique_id(
                asset=asset,
                vulnerability_id=vulnerability_id,
                finding_name=finding_name,
                cvss=cvss,
            )

            finding = Finding(
                title=finding_name,
                test=test,
                severity=severity,
                description=description,
                mitigation=mitigation,
                cvssv3=cvss,
                active=self.is_active(status),
                verified=False,
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=unique_id,
            )

            findings.append(finding)

        return findings

    def build_description(
        self,
        asset,
        vulnerability_id,
        status,
        vulnerability_type,
        risk_devoteam,
        risk_ses,
        remediation_owner,
        target_closure_date,
        evidence_for_closure,
        cleaning_steps,
        additional_comments,
    ):
        return f"""
Asset: {asset}
Vulnerability ID: {vulnerability_id}
Status: {status}
Vulnerability Type: {vulnerability_type}
Risk According to Devoteam: {risk_devoteam}
Risk According to SES: {risk_ses}
SES Remediation Owner: {remediation_owner}
Target Closure Date: {target_closure_date}
Justification / Evidence for Closure: {evidence_for_closure}
SES Cleaning Steps: {cleaning_steps}
SES Additional Comments and Notes: {additional_comments}
""".strip()

    def build_mitigation(
        self,
        recommendation_description,
        recommendation_type_detail,
    ):
        return f"""
Devoteam Recommendation Description:
{recommendation_description}

Recommendation Type Detail:
{recommendation_type_detail}
""".strip()

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

    def is_active(self, status):
        status = self.clean(status).lower()

        closed_statuses = [
            "closed",
            "done",
            "completed",
            "resolved",
            "fixed",
            "mitigated",
            "accepted",
            "risk accepted",
        ]

        if status in closed_statuses:
            return False

        return True

    def generate_unique_id(self, asset, vulnerability_id, finding_name, cvss):
        raw_value = f"{asset}|{vulnerability_id}|{finding_name}|{cvss}"
        return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()