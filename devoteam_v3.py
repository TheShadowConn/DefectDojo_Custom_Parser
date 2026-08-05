import json
import hashlib
import re

from django.conf import settings
from dojo.models import Finding

if not settings.V3_FEATURE_LOCATIONS:
    from dojo.models import Endpoint

from dojo.tools.locations import LocationData


class DevoteamScanResultV3Parser:
    def get_scan_types(self):
        return ["Devoteam Scan Result V3"]

    def get_label_for_scan_types(self, scan_type):
        return "Devoteam Scan Result V3"

    def get_description_for_scan_types(self, scan_type):
        return "Parser for Devoteam / pentest JSON scan results with CVSS and V3 Locations support."

    def get_findings(self, filename, test):
        findings = []

        data = self.load_json(filename)

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

            vulnerability_id = self.clean(item.get("Vulnerability ID"))
            asset = self.clean(item.get("Asset"))
            url = self.clean(item.get("URL"))
            ip = self.clean(item.get("IP"))
            vulnerability_type = self.clean(item.get("Vulnerability Type"))
            severity = self.map_severity(item.get("Severity"))
            description_value = self.clean(item.get("Description"))
            details = self.clean(item.get("Details"))
            impact = self.clean(item.get("Impact"))
            recommendations = self.clean(item.get("Recommendations"))
            cvss = self.clean(item.get("CVSS"))

            title = description_value
            if not title or title == "N/A":
                title = vulnerability_id if vulnerability_id != "N/A" else "Untitled Finding"

            description = self.build_description(
                vulnerability_id=vulnerability_id,
                asset=asset,
                url=url,
                ip=ip,
                vulnerability_type=vulnerability_type,
                description_value=description_value,
                details=details,
                cvss=cvss,
            )

            finding_kwargs = {
                "title": title,
                "test": test,
                "severity": severity,
                "description": description,
                "mitigation": recommendations if recommendations != "N/A" else "",
                "impact": impact if impact != "N/A" else "",
                "active": True,
                "verified": False,
                "static_finding": False,
                "dynamic_finding": True,
                "unique_id_from_tool": self.generate_unique_id(
                    vulnerability_id=vulnerability_id,
                    asset=asset,
                    title=title,
                    severity=severity,
                    cvss=cvss,
                ),
                "vuln_id_from_tool": vulnerability_id if vulnerability_id != "N/A" else "",
            }

            self.add_cvss_to_finding_kwargs(finding_kwargs, cvss)

            finding = Finding(**finding_kwargs)

            self.attach_asset_to_host_or_location(finding, asset, ip, url)

            findings.append(finding)

        return findings

    def load_json(self, filename):
        raw_data = filename.read()

        if isinstance(raw_data, bytes):
            for encoding in ["utf-8-sig", "utf-8", "cp1252", "latin1"]:
                try:
                    raw_data = raw_data.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue

        return json.loads(raw_data)

    def build_description(
        self,
        vulnerability_id,
        asset,
        url,
        ip,
        vulnerability_type,
        description_value,
        details,
        cvss,
    ):
        return f"""
Vulnerability ID: {vulnerability_id}
Asset Name: {asset}
URL: {url}
IP: {ip}
Vulnerability Type: {vulnerability_type}
CVSS: {cvss}

Description:
{description_value}

Details:
{details}
""".strip()

    def add_cvss_to_finding_kwargs(self, finding_kwargs, cvss):
        if not cvss or cvss == "N/A":
            return

        cvss = cvss.strip()

        # CVSS vector, example:
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        if cvss.upper().startswith("CVSS:"):
            finding_kwargs["cvssv3"] = cvss
            return

        # Numeric score, example: 8.8
        try:
            score = float(cvss)
            if 0.0 <= score <= 10.0:
                finding_kwargs["cvssv3_score"] = score
        except ValueError:
            return

    def attach_asset_to_host_or_location(self, finding, asset, ip, url):
        host_value = self.get_best_host_value(asset, ip, url)

        if not host_value:
            return

        if settings.V3_FEATURE_LOCATIONS:
            location = LocationData.url(host=host_value)

            if not hasattr(finding, "unsaved_locations") or finding.unsaved_locations is None:
                finding.unsaved_locations = []

            finding.unsaved_locations.append(location)

        else:
            endpoint = Endpoint(host=host_value)

            if not hasattr(finding, "unsaved_endpoints") or finding.unsaved_endpoints is None:
                finding.unsaved_endpoints = []

            finding.unsaved_endpoints.append(endpoint)

    def get_best_host_value(self, asset, ip, url):
        ip = self.clean(ip)
        asset = self.clean(asset)
        url = self.clean(url)

        if ip and ip != "N/A":
            return ip

        if url and url != "N/A":
            return self.extract_host_from_url(url)

        if asset and asset != "N/A":
            return self.normalize_asset_for_host(asset)

        return ""

    def extract_host_from_url(self, url):
        value = self.clean(url)

        value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
        value = value.split("/")[0]
        value = value.split(":")[0]

        return self.normalize_asset_for_host(value)

    def normalize_asset_for_host(self, asset):
        value = self.clean(asset)

        if not value or value == "N/A":
            return ""

        value = value.strip()

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            return value

        value = value.lower()
        value = re.sub(r"[^a-z0-9.-]+", "-", value)
        value = re.sub(r"-+", "-", value)
        value = value.strip("-.")

        return value

    def clean(self, value):
        if value is None:
            return "N/A"

        value = str(value)

        replacements = {
            "\ufeff": "",
            "\u00a0": " ",
            "Â": "",
            "â€™": "'",
            "â€˜": "'",
            "â€œ": '"',
            "â€": '"',
            "â€“": "-",
            "â€”": "-",
            "\\_": "_",
        }

        for old, new in replacements.items():
            value = value.replace(old, new)

        value = value.replace("\r\n", "\n").replace("\r", "\n")
        value = value.strip()

        if value == "":
            return "N/A"

        return value

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

    def generate_unique_id(self, vulnerability_id, asset, title, severity, cvss):
        raw_value = f"{vulnerability_id}|{asset}|{title}|{severity}|{cvss}"
        return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
