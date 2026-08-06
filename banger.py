import hashlib
import json
import re

from django.conf import settings
from dojo.models import Finding, Endpoint
from dojo.tools.locations import LocationData


class IngestV3Parser:
    def get_scan_types(self):
        return ["IngestV3Parser"]

    def get_label_for_scan_types(self, scan_type):
        return "IngestV3Parser"

    def get_description_for_scan_types(self, scan_type):
        return "Parser for Devoteam and SES pentest finding JSON converted from CSV/XLSX."

    def get_findings(self, filename, test):
        findings = []
        data = json.load(filename)

        if isinstance(data, dict):
            items = (
                data.get("vulnerabilities")
                or data.get("findings")
                or data.get("results")
                or data.get("items")
                or []
            )
        elif isinstance(data, list):
            items = data
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue

            asset = self.pick(
                item,
                [
                    "Asset",
                    "Host",
                    "Hostname",
                    "Affected Asset",
                    "Affected Host",
                    "Target",
                    "Endpoint",
                ],
            )

            url = self.pick(
                item,
                [
                    "URL",
                    "Uri",
                    "URI",
                    "Link",
                ],
            )

            ip = self.pick(
                item,
                [
                    "IP",
                    "IP Address",
                    "Host IP",
                    "Address",
                ],
            )

            vulnerability_id = self.pick(
                item,
                [
                    "Vulnerability ID",
                    "Vuln ID",
                    "Finding ID",
                    "ID",
                ],
            )

            status = self.pick(
                item,
                [
                    "Status",
                    "State",
                ],
            )

            vulnerability_type = self.pick(
                item,
                [
                    "Vulnerability Type",
                    "Type",
                    "Finding Type",
                ],
            )

            finding_name = self.pick(
                item,
                [
                    "Finding Name",
                    "Devoteam Findings",
                    "Title",
                    "Name",
                    "Vulnerability Name",
                    "Vulnerability Type",
                ],
            )

            severity_value = self.pick(
                item,
                [
                    "Risk According to SES",
                    "Risk According to Devoteam",
                    "Severity",
                    "Risk",
                ],
            )

            cvss = self.pick(
                item,
                [
                    "CVSS",
                    "CVSS according to Devoteam",
                    "CVSS Score",
                    "CVSS Risk",
                ],
            )

            description_text = self.pick(
                item,
                [
                    "Description",
                    "Summary",
                ],
            )

            details = self.pick(
                item,
                [
                    "Details",
                    "Technical Details",
                    "Observation",
                    "Finding Details",
                ],
            )

            impact = self.pick(
                item,
                [
                    "Impact",
                    "SES Contextual Comments on Impact",
                    "Business Impact",
                    "Security Impact",
                ],
            )

            recommendation = self.pick(
                item,
                [
                    "Recommendations",
                    "Devoteam recommendations Description",
                    "Devoteam recommendations",
                    "Recommendation",
                    "Remediation",
                    "Solution",
                ],
            )

            recommendation_type_detail = self.pick(
                item,
                [
                    "Recommendation Type Detail",
                    "Recommendation Detail",
                    "Remediation Detail",
                ],
            )

            remediation_owner = self.pick(
                item,
                [
                    "SES Remediation Owner",
                    "Remediation Owner",
                    "Owner",
                ],
            )

            target_closure_date = self.pick(
                item,
                [
                    "Target Closure Date (DD.MM.YYYY)",
                    "Target Closure Date",
                    "Closure Date",
                    "Due Date",
                ],
            )

            evidence_for_closure = self.pick(
                item,
                [
                    "Justification / Evidence for Closure",
                    "Evidence for Closure",
                    "Evidence",
                ],
            )

            cleaning_steps = self.pick(
                item,
                [
                    "SES Cleaning Steps",
                    "Cleaning Steps",
                    "Remediation Steps",
                ],
            )

            additional_comments = self.pick(
                item,
                [
                    "SES Additional Comments and Notes",
                    "Additional Comments",
                    "Comments",
                    "Notes",
                ],
            )

            references = self.pick(
                item,
                [
                    "References",
                    "Reference",
                    "Links",
                ],
            )

            source_file = self.pick(
                item,
                [
                    "Source File",
                    "Filename",
                    "File",
                ],
            )

            if not finding_name:
                finding_name = vulnerability_type or vulnerability_id or "Untitled Devoteam Finding"

            severity = self.map_severity(severity_value)

            description = self.build_description(
                asset=asset,
                url=url,
                ip=ip,
                vulnerability_id=vulnerability_id,
                status=status,
                vulnerability_type=vulnerability_type,
                cvss=cvss,
                description_text=description_text,
                details=details,
                impact=impact,
                remediation_owner=remediation_owner,
                target_closure_date=target_closure_date,
                evidence_for_closure=evidence_for_closure,
                cleaning_steps=cleaning_steps,
                additional_comments=additional_comments,
                source_file=source_file,
            )

            mitigation = self.build_mitigation(
                recommendation=recommendation,
                recommendation_type_detail=recommendation_type_detail,
            )

            unique_id = self.generate_unique_id(
                asset=asset,
                url=url,
                ip=ip,
                vulnerability_id=vulnerability_id,
                finding_name=finding_name,
                cvss=cvss,
            )

            kwargs = {
                "title": finding_name,
                "test": test,
                "severity": severity,
                "description": description,
                "mitigation": mitigation,
                "impact": impact,
                "references": references,
                "active": self.is_active(status),
                "verified": False,
                "static_finding": False,
                "dynamic_finding": True,
                "unique_id_from_tool": unique_id,
            }

            cvss_vector = self.extract_cvss_vector(cvss)
            if cvss_vector:
                kwargs["cvssv3"] = cvss_vector

         
