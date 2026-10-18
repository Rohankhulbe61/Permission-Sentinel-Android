"""
Permission Sentinel - Permission Evolution Intelligence Engine
Compares two application versions (APKs, Manifests, or JSON Reports)
and detects added, removed, unchanged permissions, risk score delta,
and privacy impact evolution.
"""

import logging
from typing import Dict, Any, List, Optional
from app.engine.analyzer import analyze_app
from app.database import get_all_policies

logger = logging.getLogger(__name__)


def compare_app_versions(
    old_app_data: Dict[str, Any],
    new_app_data: Dict[str, Any],
    active_policies: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Compares two app versions and computes permission diff, risk delta, and privacy impact.

    old_app_data / new_app_data structure:
    {
        "app_name": str,
        "package_name": str,
        "version": str,
        "version_code": str,
        "purpose": str,
        "permissions": List[str],
        "description": Optional[str]
    }
    """
    # 1. Package Name Validation
    old_package = old_app_data.get("package_name", "").strip()
    new_package = new_app_data.get("package_name", "").strip()

    if old_package and new_package and old_package.lower() != new_package.lower():
        raise ValueError(
            f"Package Mismatch Error: Older version package is '{old_package}' while newer version package is '{new_package}'. "
            f"Permission Evolution Intelligence requires both files to represent the same application package."
        )

    effective_package = new_package or old_package or "com.example.application"
    effective_app_name = new_app_data.get("app_name") or old_app_data.get("app_name") or "Application"

    if active_policies is None:
        try:
            active_policies = get_all_policies()
        except Exception:
            active_policies = []

    # 2. Analyze both versions using the SAME analyzer engine and policies
    old_analysis = analyze_app(
        app_name=effective_app_name,
        package_name=effective_package,
        permissions=old_app_data.get("permissions", []),
        purpose=old_app_data.get("purpose", "General App"),
        purpose_source=old_app_data.get("purpose_source", "inferred"),
        input_source="evolution-baseline",
        version=old_app_data.get("version", "1.0.0"),
        active_policies=active_policies,
        metadata={"description": old_app_data.get("description", "")}
    )

    new_analysis = analyze_app(
        app_name=effective_app_name,
        package_name=effective_package,
        permissions=new_app_data.get("permissions", []),
        purpose=new_app_data.get("purpose", "General App"),
        purpose_source=new_app_data.get("purpose_source", "inferred"),
        input_source="evolution-upgrade",
        version=new_app_data.get("version", "2.0.0"),
        active_policies=active_policies,
        metadata={"description": new_app_data.get("description", "")}
    )

    # 3. Set-based Permission Diff
    old_perms = set(old_app_data.get("permissions", []))
    new_perms = set(new_app_data.get("permissions", []))

    added_perms = sorted(list(new_perms - old_perms))
    removed_perms = sorted(list(old_perms - new_perms))
    unchanged_perms = sorted(list(old_perms & new_perms))

    # Map findings by permission identifier
    old_findings_map = {f["permission"]: f for f in old_analysis.get("permission_findings", [])}
    new_findings_map = {f["permission"]: f for f in new_analysis.get("permission_findings", [])}

    # Added Findings Detail
    added_findings = []
    for perm in added_perms:
        finding = new_findings_map.get(perm)
        if finding:
            added_findings.append({
                "permission": perm,
                "label": finding.get("label", perm.split(".")[-1]),
                "status": finding.get("status", "unexpected"),
                "severity": finding.get("severity", "medium"),
                "reason": finding.get("reason", "Newly added permission in updated version."),
                "data_exposed": finding.get("data_exposed", ""),
                "recommendation": finding.get("recommendation", "Review whether this newly added permission is necessary.")
            })
        else:
            added_findings.append({
                "permission": perm,
                "label": perm.split(".")[-1],
                "status": "unexpected",
                "severity": "medium",
                "reason": "Newly added permission in updated version.",
                "data_exposed": "",
                "recommendation": "Review whether this newly added permission is necessary."
            })

    # Removed Findings Detail
    removed_findings = []
    for perm in removed_perms:
        finding = old_findings_map.get(perm)
        label = finding.get("label", perm.split(".")[-1]) if finding else perm.split(".")[-1]
        removed_findings.append({
            "permission": perm,
            "label": label,
            "status": "removed",
            "severity": "low",
            "reason": "Permission removed in updated version (Invasiveness Reduced)."
        })

    # Changed Classifications Detail
    changed_classifications = []
    for perm in unchanged_perms:
        old_f = old_findings_map.get(perm)
        new_f = new_findings_map.get(perm)
        if old_f and new_f:
            if old_f.get("status") != new_f.get("status") or old_f.get("severity") != new_f.get("severity"):
                changed_classifications.append({
                    "permission": perm,
                    "label": new_f.get("label", perm.split(".")[-1]),
                    "old_status": old_f.get("status"),
                    "new_status": new_f.get("status"),
                    "old_severity": old_f.get("severity"),
                    "new_severity": new_f.get("severity"),
                    "reason": new_f.get("reason", "Classification or severity changed in updated context.")
                })

    # 4. Risk Score Delta Calculation
    old_score = old_analysis.get("score", 0)
    new_score = new_analysis.get("score", 0)
    score_delta = new_score - old_score

    old_risk_band = old_analysis.get("risk_band", "Low")
    new_risk_band = new_analysis.get("risk_band", "Low")

    if score_delta > 0:
        summary_explanation = f"Risk score increased by +{score_delta} (from {old_score}/100 to {new_score}/100). The updated version introduced {len(added_perms)} new permission(s)."
    elif score_delta < 0:
        summary_explanation = f"Risk score decreased by {score_delta} (from {old_score}/100 to {new_score}/100). The updated version removed {len(removed_perms)} permission(s)."
    else:
        summary_explanation = f"Risk score remains unchanged at {new_score}/100 across version upgrade."

    # 5. Recommendations for Evolution
    evolution_recommendations = []
    if added_perms:
        short_added = ", ".join([p.split(".")[-1] for p in added_perms[:3]])
        evolution_recommendations.append(
            f"Review {len(added_perms)} newly added permission(s) ({short_added}) against the app's official release notes."
        )
    if any(f.get("severity") in ["high", "critical"] for f in added_findings):
        evolution_recommendations.append(
            "High-sensitivity permissions were introduced in the updated version. Confirm explicit user consent before upgrading."
        )
    if not evolution_recommendations:
        evolution_recommendations.append("Permission evolution analysis complete. No invasive permission anomalies detected in version upgrade.")

    return {
        "package_name": effective_package,
        "app_name": effective_app_name,
        "old_version": old_app_data.get("version", "1.0.0"),
        "old_version_code": old_app_data.get("version_code", ""),
        "new_version": new_app_data.get("version", "2.0.0"),
        "new_version_code": new_app_data.get("version_code", ""),
        "old_score": old_score,
        "new_score": new_score,
        "score_delta": score_delta,
        "old_risk_band": old_risk_band,
        "new_risk_band": new_risk_band,
        "summary_explanation": summary_explanation,
        "added_permissions": added_perms,
        "removed_permissions": removed_perms,
        "unchanged_permissions": unchanged_perms,
        "added_findings": added_findings,
        "removed_findings": removed_findings,
        "changed_classifications": changed_classifications,
        "advertised_features": new_analysis.get("metadata", {}).get("advertised_features", []),
        "recommendations": evolution_recommendations,
        "old_analysis": old_analysis,
        "new_analysis": new_analysis
    }
