"""
Permission Sentinel - Analysis Engine
Pure, deterministic analysis module with metadata service & feature extraction integration.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Set, Dict, Any

from app.config import (
    KNOWLEDGE_BASE_DIR,
    KNOWLEDGE_BASE_VERSION,
    SENSITIVITY_WEIGHTS,
    SENSITIVITY_CAP,
    PURPOSE_MISMATCH_PER_PERMISSION,
    PURPOSE_MISMATCH_CAP,
    COMBINATION_RULE_SCORE,
    COMBINATION_RULE_CAP,
    POLICY_VIOLATION_SCORE,
    POLICY_VIOLATION_CAP,
    CONTEXT_AMPLIFIER_MAX,
    get_risk_band,
    PURPOSE_CATEGORIES,
)
from app.engine.metadata_service import get_play_store_metadata
from app.engine.feature_extractor import extract_advertised_features
from app.engine.feature_permission_mapper import get_permissions_for_features, FEATURE_TO_PERMISSIONS

# === Knowledge Base Loading ===

_kb_cache = None


def load_knowledge_base() -> dict:
    """Load permissions and combination rules from JSON knowledge base."""
    global _kb_cache
    if _kb_cache is not None:
        return _kb_cache

    kb_file = KNOWLEDGE_BASE_DIR / "permissions_kb.json"
    if kb_file.exists():
        with open(kb_file, "r", encoding="utf-8") as f:
            _kb_cache = json.load(f)
    else:
        _kb_cache = {"permissions": {}, "combination_rules": []}

    return _kb_cache


def get_permission_info(permission: str) -> Optional[dict]:
    """Look up a permission in the knowledge base."""
    kb = load_knowledge_base()
    return kb.get("permissions", {}).get(permission)


def get_combination_rules() -> list[dict]:
    """Get all combination rules from the knowledge base."""
    kb = load_knowledge_base()
    return kb.get("combination_rules", [])


def infer_purpose(app_name: str, package_name: str) -> Optional[str]:
    """Attempt to infer app purpose from name/package keywords."""
    combined = (app_name + " " + package_name).lower()

    keyword_map = {
        "Calculator / Simple Utility": ["calculator", "calc", "converter", "unit", "flashlight", "torch", "clock", "timer", "stopwatch"],
        "Notes / Productivity": ["notes", "note", "todo", "task", "productivity", "editor", "document", "office"],
        "Maps / Navigation": ["maps", "map", "navigation", "navigate", "gps", "directions", "route"],
        "Messaging / Communication": ["messenger", "message", "chat", "whatsapp", "telegram", "signal", "call", "phone", "sms", "email", "mail"],
        "Camera / Photo Editor": ["camera", "photo", "picture", "image", "gallery", "snap", "lens"],
        "Music / Media Player": ["music", "player", "audio", "spotify", "podcast", "radio", "video", "media", "stream"],
        "Fitness / Activity Tracking": ["fitness", "fit", "exercise", "workout", "health", "step", "run", "track", "activity"],
        "Weather": ["weather", "forecast", "climate", "temperature", "rain"],
        "E-commerce": ["shop", "store", "buy", "market", "amazon", "ebay", "cart", "order", "commerce"],
        "Browser": ["browser", "chrome", "firefox", "safari", "web", "surf"],
        "Finance / Banking": ["bank", "finance", "pay", "money", "wallet", "investment", "stock", "crypto"],
        "Game": ["game", "play", "puzzle", "arcade", "racing", "adventure", "strategy"],
    }

    for purpose, keywords in keyword_map.items():
        for kw in keywords:
            if kw in combined:
                return purpose

    return None


# === Permission Classification ===

def classify_permission(
    permission: str,
    purpose: str,
    active_policies: list[dict],
    feature_permissions: Set[str] = None,
    advertised_features: List[Dict[str, Any]] = None
) -> dict:
    """Classify a single permission's relevance to stated purpose and advertised features."""
    info = get_permission_info(permission)

    # Check policy violations first
    policy_violation = check_policy_violation(permission, purpose, active_policies)
    if policy_violation:
        return policy_violation

    if info is None:
        # Unknown permission - not in KB
        return {
            "permission": permission,
            "label": permission.split(".")[-1].replace("_", " ").title() if "." in permission else permission,
            "status": "unknown",
            "severity": "unknown",
            "base_weight": SENSITIVITY_WEIGHTS["unknown"],
            "reason": f"Permission '{permission}' is not catalogued in knowledge base (v{KNOWLEDGE_BASE_VERSION}). Needs Review.",
            "evidence_rule_ids": ["KB-UNKNOWN"],
            "confidence": "low: permission uncatalogued",
            "recommendation": "Review this permission manually in official Android documentation.",
            "data_exposed": "Unknown - permission uncatalogued",
            "caveat": "This permission may be legitimate but is not yet catalogued in the knowledge base.",
        }

    label = info.get("label", permission)
    sensitivity = info.get("sensitivity", "unknown")
    base_weight = SENSITIVITY_WEIGHTS.get(sensitivity, 0)
    data_exposed = info.get("data_exposed", "")
    family = info.get("family", "unknown")
    explanation = info.get("explanation", "")
    notes = info.get("notes", "")
    safer_alt = info.get("safer_alternative")

    expected_purposes = info.get("expected_purposes", [])
    unexpected_purposes = info.get("unexpected_purposes", [])

    is_unknown_purpose = purpose == "Other / Unknown"

    # Check if permission is directly supported by an advertised feature
    supported_by_feature = feature_permissions is not None and permission in feature_permissions
    matching_feat = None
    if supported_by_feature and advertised_features:
        for feat in advertised_features:
            fid = feat.get("feature_id")
            if fid in FEATURE_TO_PERMISSIONS and permission in FEATURE_TO_PERMISSIONS[fid]:
                matching_feat = feat
                break

    # Determine status
    if purpose in expected_purposes:
        status = "expected"
        reason = f"'{label}' is commonly expected for '{purpose}' apps. {explanation}"
        confidence = "high: knowledge base explicit match"
        recommendation = f"Typical permission for this category. Verify it is used for intended features."
        caveat = ""
    elif supported_by_feature:
        status = "context-dependent"
        feat_label = matching_feat.get("label", "Advertised Feature") if matching_feat else "Listing Feature"
        evidence = matching_feat.get("evidence_phrase", "") if matching_feat else ""
        reason = f"'{label}' is supported by advertised feature in Play Store listing: '{feat_label}' ({evidence})."
        confidence = f"high: supported by Play Store listing description"
        recommendation = f"Verify that feature '{feat_label}' is used as advertised."
        caveat = "Supported by app store listing features."
    elif purpose in unexpected_purposes and not is_unknown_purpose:
        status = "unexpected"
        reason = f"'{label}' is usually not needed for '{purpose}' apps. {explanation} {notes}"
        confidence = "high confidence: explicit purpose mismatch in knowledge base"
        recommendation = f"Review whether this permission is necessary. "
        if safer_alt:
            recommendation += f"Consider: {safer_alt}"
        else:
            recommendation += "Consider removing it or using a less privileged alternative."
        caveat = f"The app may legitimately need this permission for an optional feature not captured by '{purpose}'."
    else:
        status = "context-dependent"
        reason = f"'{label}' is not explicitly expected for '{purpose}' apps, but may support optional features. {explanation}"
        confidence = "heuristic: sensitive permission without explicit purpose match"
        recommendation = "Verify this permission is used for a feature the user expects."
        if safer_alt:
            recommendation += f" Consider: {safer_alt}"
        caveat = "May be justified by an optional feature."

    evidence_ids = [f"KB-{sensitivity.upper()}-{family.upper()}"]

    return {
        "permission": permission,
        "label": label,
        "status": status,
        "severity": sensitivity,
        "base_weight": base_weight,
        "reason": reason,
        "evidence_rule_ids": evidence_ids,
        "confidence": confidence,
        "recommendation": recommendation,
        "data_exposed": data_exposed,
        "caveat": caveat,
    }


def check_policy_violation(permission: str, purpose: str, active_policies: list[dict]) -> Optional[dict]:
    """Check if a permission violates any active policy."""
    info = get_permission_info(permission)
    label = info.get("label", permission) if info else permission
    sensitivity = info.get("sensitivity", "unknown") if info else "unknown"
    family = info.get("family", "unknown") if info else "unknown"
    data_exposed = info.get("data_exposed", "Unknown") if info else "Unknown"

    for policy in active_policies:
        if not policy.get("enabled", True):
            continue

        pj = policy.get("policy_json", {})
        blocked = pj.get("blocked_permissions", [])

        if permission in blocked:
            return {
                "permission": permission,
                "label": label,
                "status": "policy-violation",
                "severity": "critical",
                "base_weight": 35,
                "reason": f"VIOLATION: Permission '{label}' is explicitly blocked by active policy '{policy.get('name', 'Default Policy')}'.",
                "evidence_rule_ids": [f"POLICY-{policy.get('id', 'BLOCKED')}"],
                "confidence": "deterministic: policy block rule",
                "recommendation": f"Remove this permission to comply with organization policy '{policy.get('name')}'.",
                "data_exposed": data_exposed,
                "caveat": "Explicit policy violation.",
            }

    return None


def evaluate_combination_rules(permissions: list[str], purpose: str) -> list[dict]:
    """Evaluate all combination rules against the declared permissions."""
    rules = get_combination_rules()
    perm_set = set(permissions)
    findings = []

    for rule in rules:
        rule_id = rule.get("rule_id", "COMBO-UNKNOWN")
        trigger_perms = rule.get("trigger_permissions", [])

        if not trigger_perms:
            continue

        matched = [p for p in trigger_perms if p in perm_set]

        if len(matched) == len(trigger_perms):
            findings.append({
                "rule_id": rule_id,
                "matched_permissions": sorted(set(matched)),
                "explanation": rule.get("explanation", ""),
                "confidence": rule.get("confidence", "heuristic"),
                "recommendation": rule.get("recommendation", ""),
                "severity": rule.get("severity", "medium"),
            })

    return findings


# === Score Computation ===

def compute_score(
    permission_findings: list[dict],
    combination_findings: list[dict],
    purpose: str,
) -> tuple[int, dict]:
    """Compute the transparent risk score and breakdown."""
    breakdown = {
        "sensitivity_score": 0,
        "purpose_mismatch_score": 0,
        "combination_score": 0,
        "policy_violation_score": 0,
        "context_amplifier_score": 0,
        "total": 0,
        "details": {
            "sensitivity_permissions": [],
            "unexpected_permissions": [],
            "combination_rules_triggered": [],
            "policy_violations": [],
            "context_amplifiers": [],
        }
    }

    weights = []
    for f in permission_findings:
        st = f.get("status")
        w = f.get("base_weight", 0)
        if st in ("unexpected", "policy-violation"):
            eff_w = round(w * 0.35)
        elif st == "context-dependent":
            eff_w = round(w * 0.15)
        else:
            eff_w = 0

        if eff_w > 0:
            weights.append((eff_w, f["permission"]))

    weights.sort(reverse=True)
    top_3 = weights[:3]
    sensitivity_score = min(sum(w for w, _ in top_3), SENSITIVITY_CAP)
    breakdown["sensitivity_score"] = sensitivity_score
    breakdown["details"]["sensitivity_permissions"] = [
        {"permission": p, "weight": w} for w, p in top_3
    ]

    unexpected_count = 0
    unexpected_perms = []
    for f in permission_findings:
        if f["status"] == "unexpected":
            unexpected_count += 1
            unexpected_perms.append(f["permission"])

    mismatch_score = min(unexpected_count * PURPOSE_MISMATCH_PER_PERMISSION, PURPOSE_MISMATCH_CAP)
    breakdown["purpose_mismatch_score"] = mismatch_score
    breakdown["details"]["unexpected_permissions"] = unexpected_perms

    combo_count = len(combination_findings)
    combo_score = min(combo_count * COMBINATION_RULE_SCORE, COMBINATION_RULE_CAP)
    breakdown["combination_score"] = combo_score
    breakdown["details"]["combination_rules_triggered"] = [
        cf["rule_id"] for cf in combination_findings
    ]

    policy_violations = [f for f in permission_findings if f["status"] == "policy-violation"]
    policy_score = min(len(policy_violations) * POLICY_VIOLATION_SCORE, POLICY_VIOLATION_CAP)
    breakdown["policy_violation_score"] = policy_score
    breakdown["details"]["policy_violations"] = [f["permission"] for f in policy_violations]

    amplifier_score = 0
    amplifier_details = []

    has_bg = any(
        f["permission"] in (
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        )
        for f in permission_findings
    )
    has_critical_unexpected = any(
        f["status"] == "unexpected" and f["severity"] == "critical"
        for f in permission_findings
    )

    if has_bg and has_critical_unexpected:
        amp = min(8, CONTEXT_AMPLIFIER_MAX)
        amplifier_score += amp
        amplifier_details.append({
            "reason": "Critical unexpected permission combined with background service capability",
            "contribution": amp,
        })

    amplifier_score = min(amplifier_score, CONTEXT_AMPLIFIER_MAX)
    breakdown["context_amplifier_score"] = amplifier_score
    breakdown["details"]["context_amplifiers"] = amplifier_details

    total = sensitivity_score + mismatch_score + combo_score + policy_score + amplifier_score
    total = max(0, min(100, total))
    breakdown["total"] = total

    return total, breakdown


# === Main Analysis Function ===

def analyze_app(
    app_name: str,
    package_name: str,
    permissions: list[str],
    purpose: str,
    purpose_source: str = "user-selected",
    input_source: str = "manual",
    version: str = "",
    target_sdk: str = "",
    active_policies: list[dict] = None,
    metadata: dict = None,
) -> dict:
    """Run the feature-aware permission analysis pipeline."""
    if active_policies is None:
        active_policies = []
    if metadata is None:
        metadata = {}

    permissions = sorted(set(p.strip() for p in permissions if p.strip()))

    # Retrieve Google Play Store metadata and extract advertised features
    play_meta = get_play_store_metadata(package_name, app_name)
    desc = play_meta.get("description", "")
    advertised_features = extract_advertised_features(desc, app_name, package_name)
    feature_permissions = get_permissions_for_features(advertised_features)

    # Classify each permission
    permission_findings = []
    for perm in permissions:
        finding = classify_permission(
            perm,
            purpose,
            active_policies,
            feature_permissions=feature_permissions,
            advertised_features=advertised_features
        )
        permission_findings.append(finding)

    # Evaluate combination rules
    combination_findings = evaluate_combination_rules(permissions, purpose)

    # Compute score
    score, score_breakdown = compute_score(permission_findings, combination_findings, purpose)
    risk_band = get_risk_band(score)

    analysis_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    metadata.update({
        "play_store": play_meta,
        "advertised_features": advertised_features,
        "has_play_store_listing": play_meta.get("has_listing", False),
        "metadata_source": play_meta.get("metadata_source", "Device Scan")
    })

    result = {
        "id": analysis_id,
        "package_name": package_name,
        "app_name": app_name,
        "version": version,
        "target_sdk": target_sdk,
        "selected_purpose": purpose,
        "purpose_source": purpose_source,
        "input_source": input_source,
        "created_at": now,
        "knowledge_base_version": KNOWLEDGE_BASE_VERSION,
        "score": score,
        "risk_band": risk_band,
        "score_breakdown": score_breakdown,
        "permissions": permissions,
        "permission_findings": permission_findings,
        "combination_findings": combination_findings,
        "user_notes": "",
        "metadata": metadata,
    }

    return result
