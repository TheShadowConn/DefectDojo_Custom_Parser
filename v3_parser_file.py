import hashlib
import json
import re

from dojo.models import Finding


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

            asset = self.pick(item, ["Asset", "Host", "Affected Asset", "Target"])
            url = self.pick(item, ["URL", "Uri", "Link"])
            ip = self.pick(item, ["IP", "IP Address", "Host IP"])
            vulnerability_id = self.pick(item, ["Vulnerability ID", "Vuln ID", "Finding ID", "ID"])
            status = self.pick(item, ["Status", "State"])
            vulnerability_type = self.pick(item, ["Vulnerability Type", "Type", "Finding Type"])
            finding_name = self.pick(item, ["Finding Name", "Devoteam Findings", "Title", "Name", "Vulnerability Name"])
            severity_value = self.pick(item, ["Risk According to SES", "Risk According to Devoteam", "Severity", "Risk"])
            cvss = self.pick(item, ["CVSS", "CVSS according to Devoteam", "CVSS Score", "CVSS Risk"])
            description_text = self.pick(item, ["Description", "Summary"])
            details = self.pick(item, ["Details", "Technical Details", "Observation", "Finding Details"])
            impact = self.pick(item, ["Impact", "SES Contextual Comments on Impact", "Business Impact", "Security Impact"])
            recommendation = self.pick(item, ["Recommendations", "Devoteam recommendations Description", "Devoteam recommendations", "Recommendation", "Remediation", "Solution"])
            recommendation_type_detail = self.pick(item, ["Recommendation Type Detail", "Recommendation Detail", "Remediation Detail"])
            remediation_owner = self.pick(item, ["SES Remediation Owner", "Remediation Owner", "Owner"])
            target_closure_date = self.pick(item, ["Target Closure Date (DD.MM.YYYY)", "Target Closure Date", "Closure Date", "Due Date"])
            evidence_for_closure = self.pick(item, ["Justification / Evidence for Closure", "Evidence for Closure", "Evidence"])
            cleaning_steps = self.pick(item, ["SES Cleaning Steps", "Cleaning Steps", "Remediation Steps"])
            additional_comments = self.pick(item, ["SES Additional Comments and Notes", "Additional Comments", "Comments", "Notes"])
            references = self.pick(item, ["References", "Reference", "Links"])
            source_file = self.pick(item, ["Source File", "Filename", "File"])

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

            finding = Finding(**kwargs)

            locations = []

            if url:
                locations.append(url)

            elif ip:
                locations.append(ip)

            elif asset:
                locations.append(asset)

            finding.unsaved_endpoints = locations

            findings.append(finding)
        return findings

    def pick(self, item, keys):
        for key in keys:
            if key in item:
                value = self.clean(item.get(key))
                if value:
                    return value
        lower_map = {str(k).strip().lower(): k for k in item.keys()}
        for key in keys:
            actual = lower_map.get(str(key).strip().lower())
            if actual is not None:
                value = self.clean(item.get(actual))
                if value:
                    return value
        return ""

    def clean(self, value):
        if value is None:
            return ""
        value = str(value)
        value = value.replace("\ufeff", "")
        value = value.replace("\u00a0", " ")
        value = value.replace("_x000D_", "\n")
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", value)
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        value = re.sub(r"[ \t]+", " ", value)
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()

    def map_severity(self, value):
        value = self.clean(value).lower()
        if value in ["critical", "crit"]:
            return "Critical"
        if value in ["high", "h"]:
            return "High"
        if value in ["medium", "med", "moderate", "m"]:
            return "Medium"
        if value in ["low", "l"]:
            return "Low"
        if value in ["info", "informational", "information"]:
            return "Info"
        try:
            score = float(re.findall(r"\d+(?:\.\d+)?", value)[0])
            if score >= 9.0:
                return "Critical"
            if score >= 7.0:
                return "High"
            if score >= 4.0:
                return "Medium"
            if score > 0.0:
                return "Low"
        except Exception:
            pass
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
            "false positive",
            "duplicate",
        ]
        return status not in closed_statuses

    def extract_cvss_vector(self, cvss):
        cvss = self.clean(cvss)
        match = re.search(r"CVSS:3\.[01]/[^\s]+", cvss, flags=re.IGNORECASE)
        if match:
            return match.group(0)
        return ""

    def build_description(
        self,
        asset,
        url,
        ip,
        vulnerability_id,
        status,
        vulnerability_type,
        cvss,
        description_text,
        details,
        impact,
        remediation_owner,
        target_closure_date,
        evidence_for_closure,
        cleaning_steps,
        additional_comments,
        source_file,
    ):
        sections = [
            ("Asset", asset),
            ("URL", url),
            ("IP", ip),
            ("Vulnerability ID", vulnerability_id),
            ("Status", status),
            ("Vulnerability Type", vulnerability_type),
            ("CVSS", cvss),
            ("Description", description_text),
            ("Details", details),
            ("Impact", impact),
            ("SES Remediation Owner", remediation_owner),
            ("Target Closure Date", target_closure_date),
            ("Justification / Evidence for Closure", evidence_for_closure),
            ("SES Cleaning Steps", cleaning_steps),
            ("SES Additional Comments and Notes", additional_comments),
            ("Source File", source_file),
        ]
        output = []
        for label, value in sections:
            value = self.clean(value)
            if value:
                output.append(f"{label}:\n{value}")
        return "\n\n".join(output) if output else "No description provided."

    def build_mitigation(self, recommendation, recommendation_type_detail):
        sections = []
        recommendation = self.clean(recommendation)
        recommendation_type_detail = self.clean(recommendation_type_detail)
        if recommendation:
            sections.append(f"Recommendation:\n{recommendation}")
        if recommendation_type_detail:
            sections.append(f"Recommendation Type Detail:\n{recommendation_type_detail}")
        return "\n\n".join(sections) if sections else "No mitigation provided."

    def generate_unique_id(self, asset, url, ip, vulnerability_id, finding_name, cvss):
        raw_value = f"{asset}|{url}|{ip}|{vulnerability_id}|{finding_name}|{cvss}"
        return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
