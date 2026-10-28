"""Version-to-CVE matching and risk assessment, separate from API transport."""

import time
from typing import Any, Dict, List


PARTIAL_MATCH_TIMEOUT_SECONDS = 5


def risk_level_for_score(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class VulnerabilityAnalyzer:
    def __init__(self, client):
        self.client = client

    def analyze_ports(self, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        analysis = {
            "total_ports": len(open_ports),
            "vulnerable_ports": [],
            "recommendations": [],
            "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        seen_cves = set()
        partial_match_deadline = None

        for port in open_ports:
            product = (port.get("product") or "").strip()
            version = (port.get("version") or "").strip()
            partial_match = not product or not version
            if partial_match:
                product = product or (port.get("service") or "").strip()
                if not product:
                    continue
                if partial_match_deadline is None:
                    partial_match_deadline = time.monotonic() + PARTIAL_MATCH_TIMEOUT_SECONDS
                if time.monotonic() >= partial_match_deadline:
                    continue

                vulnerabilities = self.client.search_vulnerabilities_by_product_version(
                    product, version, deadline=partial_match_deadline
                )
                # Preserve the old behavior for an incomplete identification when
                # the bounded lookup finds nothing or times out.
                if not vulnerabilities:
                    continue
            else:
                vulnerabilities = self.client.search_vulnerabilities_by_product_version(
                    product, version
                )

            recommendations = self.client.get_recommendations_for_product(product, version)
            scores = [item.get("cvss_score") for item in vulnerabilities]
            levels = [risk_level_for_score(score) for score in scores if score is not None]
            risk = max(
                levels,
                key=lambda level: _RISK_ORDER.get(level, -1),
                default="unknown" if vulnerabilities else "low",
            )

            # Every remote API result is a potential match unless version
            # applicability has been verified against authoritative CPE data.
            for item in vulnerabilities:
                item.setdefault("confidence", "possible")
                item.setdefault("source", "unknown")
                cve_id = item.get("cve_id")
                severity = item.get("severity")
                if cve_id and cve_id not in seen_cves and severity in analysis["risk_summary"]:
                    seen_cves.add(cve_id)
                    analysis["risk_summary"][severity] += 1

            analysis["vulnerable_ports"].append({
                "port": port.get("port"),
                "service": (port.get("service") or "").lower(),
                "product": product.lower(),
                "version": version.lower(),
                "risk_level": risk,
                "vulnerabilities": vulnerabilities,
                "recommendations": recommendations,
            })
        return analysis


_RISK_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
