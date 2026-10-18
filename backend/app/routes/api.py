"""
Permission Sentinel - API Routes
All REST endpoints for analysis, apps, policies, exports, and demo data.
"""

import os
import csv
import io
import json
import uuid
import tempfile
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import (
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_EXTENSIONS,
    DELETE_APK_AFTER_PARSE,
    UPLOAD_DIR,
    KNOWLEDGE_BASE_VERSION,
    PURPOSE_CATEGORIES,
)
from app.models import (
    AnalyzeRequest,
    PolicyCreateRequest,
    PolicyUpdateRequest,
    UpdateNotesRequest,
    HealthResponse,
)
from app.database import (
    get_all_analyses,
    get_analysis_detail,
    save_analysis,
    delete_analysis,
    delete_all_analyses,
    update_user_notes,
    get_all_policies,
    get_policy,
    save_policy,
    delete_policy,
)
from app.engine.analyzer import (
    analyze_app,
    load_knowledge_base,
    infer_purpose,
)
from app.engine.evolution import compare_app_versions
from app.parsers.manifest_parser import parse_manifest_xml, ManifestParseError
from app.parsers.report_parser import parse_json_report, parse_csv_report, ReportParseError
from app.parsers.apk_parser import is_available as apk_parser_available, parse_apk, APKParseError
from app.demo_data.fixtures import get_demo_apps, get_ground_truth

logger = logging.getLogger(__name__)
router = APIRouter()


# === Health ===

@router.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        knowledge_base_version=KNOWLEDGE_BASE_VERSION,
    )


@router.get("/api/purposes")
async def get_purposes():
    """Return available purpose categories."""
    return {"purposes": PURPOSE_CATEGORIES}


@router.get("/api/capabilities")
async def get_capabilities():
    """Return system capabilities."""
    return {
        "apk_parsing": apk_parser_available(),
        "knowledge_base_version": KNOWLEDGE_BASE_VERSION,
        "max_upload_size_mb": MAX_UPLOAD_SIZE_BYTES / (1024 * 1024),
        "supported_formats": ["apk", "xml", "json", "csv"],
    }


# === Demo ===

@router.get("/api/demo/apps")
async def get_demo_data():
    """Return demo app data for testing."""
    return {"apps": get_demo_apps()}


@router.post("/api/demo/analyze")
async def analyze_demo_apps():
    """Analyze all demo apps and save results."""
    demo_apps = get_demo_apps()
    active_policies = get_all_policies()
    results = []

    for app_data in demo_apps:
        result = analyze_app(
            app_name=app_data["app_name"],
            package_name=app_data["package_name"],
            permissions=app_data["permissions"],
            purpose=app_data["purpose"],
            purpose_source=app_data["purpose_source"],
            input_source="demo",
            version=app_data.get("version", ""),
            target_sdk=app_data.get("target_sdk", ""),
            active_policies=active_policies,
            metadata={"description": app_data.get("description", "")},
        )
        save_analysis(result)
        results.append({
            "id": result["id"],
            "app_name": result["app_name"],
            "score": result["score"],
            "risk_band": result["risk_band"],
            "finding_count": len(result["permission_findings"]),
        })

    return {"analyzed": len(results), "results": results}


@router.get("/api/demo/ground-truth")
async def get_demo_ground_truth():
    """Return ground truth labels for demo fixtures."""
    return {"ground_truth": get_ground_truth()}


# === Analysis ===

@router.post("/api/analyze/report")
async def analyze_report(request: AnalyzeRequest):
    """Analyze a single app from a report/manual input."""
    active_policies = get_all_policies()

    result = analyze_app(
        app_name=request.app_name,
        package_name=request.package_name,
        permissions=request.permissions,
        purpose=request.purpose,
        purpose_source=request.purpose_source,
        input_source=request.source or "json-report",
        version=request.version or "",
        target_sdk=request.target_sdk or "",
        active_policies=active_policies,
        metadata={"description": request.description} if request.description else {},
    )

    save_analysis(result)
    return result


@router.post("/api/analyze/batch")
async def analyze_batch(apps: list[AnalyzeRequest]):
    """Analyze multiple apps from a batch request."""
    active_policies = get_all_policies()
    results = []

    for app_data in apps:
        result = analyze_app(
            app_name=app_data.app_name,
            package_name=app_data.package_name,
            permissions=app_data.permissions,
            purpose=app_data.purpose,
            purpose_source=app_data.purpose_source,
            input_source=app_data.source or "json-report",
            version=app_data.version or "",
            target_sdk=app_data.target_sdk or "",
            active_policies=active_policies,
            metadata={"description": app_data.description} if app_data.description else {},
        )
        save_analysis(result)
        results.append(result)

    return {"analyzed": len(results), "results": results}


@router.post("/api/analyze/upload")
async def analyze_upload(
    file: UploadFile = File(...),
    purpose: str = Form(...),
    purpose_source: str = Form(default="user-selected"),
):
    """
    Analyze an uploaded file (APK, manifest XML, JSON report, or CSV report).
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    # Get file extension
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Read file content with size check
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(content) / (1024*1024):.1f} MB). Maximum: {MAX_UPLOAD_SIZE_BYTES / (1024*1024):.0f} MB."
        )

    active_policies = get_all_policies()

    try:
        if ext == ".xml":
            return await _handle_manifest_upload(content, purpose, purpose_source, active_policies)
        elif ext == ".apk":
            return await _handle_apk_upload(content, file.filename, purpose, purpose_source, active_policies)
        elif ext == ".json":
            return await _handle_json_upload(content, purpose, purpose_source, active_policies)
        elif ext == ".csv":
            return await _handle_csv_upload(content, purpose, purpose_source, active_policies)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")
    except HTTPException:
        raise
    except ManifestParseError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ReportParseError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except APKParseError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error during file analysis")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


async def _extract_app_data_from_file_or_json(
    upload_file: Optional[UploadFile],
    json_text: Optional[str],
    default_purpose: str
) -> dict:
    """Extract app metadata and permissions from upload file or JSON string."""
    if upload_file and upload_file.filename:
        filename = upload_file.filename
        ext = Path(filename).suffix.lower()
        content = await upload_file.read()

        if ext == ".apk":
            if not apk_parser_available():
                raise HTTPException(
                    status_code=422,
                    detail="APK parsing requires Androguard. Install with: pip install androguard."
                )
            temp_name = f"{uuid.uuid4().hex}_{filename}"
            temp_path = str(UPLOAD_DIR / temp_name)
            try:
                with open(temp_path, 'wb') as f:
                    f.write(content)
                apk_res = parse_apk(temp_path, MAX_UPLOAD_SIZE_BYTES)
                return {
                    "app_name": apk_res.app_name or apk_res.package_name or filename,
                    "package_name": apk_res.package_name,
                    "version": apk_res.version_name or "1.0.0",
                    "version_code": str(apk_res.version_code or ""),
                    "permissions": apk_res.permissions,
                    "purpose": default_purpose,
                }
            finally:
                if temp_path and os.path.exists(temp_path) and DELETE_APK_AFTER_PARSE:
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
        elif ext == ".xml":
            manifest = parse_manifest_xml(content.decode('utf-8', errors='ignore'))
            return {
                "app_name": manifest.app_name or manifest.package_name,
                "package_name": manifest.package_name,
                "version": manifest.version_name or "1.0.0",
                "version_code": str(manifest.version_code or ""),
                "permissions": manifest.permissions,
                "purpose": default_purpose,
            }
        elif ext == ".json":
            records = parse_json_report(content.decode('utf-8', errors='ignore'))
            if records:
                rec = records[0]
                return {
                    "app_name": rec.app_name,
                    "package_name": rec.package_name,
                    "version": rec.version or "1.0.0",
                    "version_code": "",
                    "permissions": rec.permissions,
                    "purpose": rec.purpose or default_purpose,
                    "description": rec.description
                }

    if json_text and json_text.strip():
        try:
            data = json.loads(json_text)
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            return {
                "app_name": data.get("app_name", "Application"),
                "package_name": data.get("package_name", ""),
                "version": data.get("version") or data.get("version_name") or "1.0.0",
                "version_code": str(data.get("version_code") or ""),
                "permissions": data.get("permissions", []),
                "purpose": data.get("purpose") or data.get("selected_purpose") or default_purpose,
                "description": data.get("description", "")
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON format for comparison: {str(e)}")

    return {"permissions": []}


@router.post("/api/analyze/compare")
async def analyze_compare_versions(
    file_old: Optional[UploadFile] = File(None),
    file_new: Optional[UploadFile] = File(None),
    report_old_json: Optional[str] = Form(None),
    report_new_json: Optional[str] = Form(None),
    purpose: str = Form(default="General App")
):
    """
    Compare two app versions (APKs, Manifest XMLs, or JSON Reports) for Permission Evolution Intelligence.
    Option A: Upload two APK files (file_old & file_new).
    Option B: Submit two JSON report strings (report_old_json & report_new_json).
    """
    old_data = await _extract_app_data_from_file_or_json(file_old, report_old_json, purpose)
    new_data = await _extract_app_data_from_file_or_json(file_new, report_new_json, purpose)

    if not old_data.get("permissions") or not new_data.get("permissions"):
        raise HTTPException(
            status_code=400,
            detail="Permission Evolution Intelligence requires valid permission declarations for both older and newer app versions."
        )

    active_policies = get_all_policies()

    try:
        evolution_result = compare_app_versions(old_data, new_data, active_policies=active_policies)
        return evolution_result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Error during version evolution analysis")
        raise HTTPException(status_code=500, detail=f"Evolution comparison failed: {str(e)}")


async def _handle_manifest_upload(content: bytes, purpose: str, purpose_source: str, policies: list):
    """Handle manifest XML upload."""
    try:
        text_content = content.decode('utf-8')
        manifest = parse_manifest_xml(text_content)
    except UnicodeDecodeError:
        # Might be binary manifest
        manifest = parse_manifest_xml(content)

    # Infer purpose if needed
    suggested_purpose = infer_purpose(manifest.app_name, manifest.package_name)

    app_result = analyze_app(
        app_name=manifest.app_name or manifest.package_name or "Unknown App",
        package_name=manifest.package_name,
        permissions=manifest.permissions,
        purpose=purpose,
        purpose_source=purpose_source,
        input_source="manifest-xml",
        version=manifest.version_name,
        target_sdk=manifest.target_sdk,
        active_policies=policies,
        metadata={
            "min_sdk": manifest.min_sdk,
            "version_code": manifest.version_code,
            "has_foreground_service": manifest.has_foreground_service,
            "has_background_service": manifest.has_background_service,
            "parse_warnings": manifest.parse_warnings,
            "suggested_purpose": suggested_purpose,
        },
    )

    save_analysis(app_result)
    return app_result


async def _handle_apk_upload(content: bytes, filename: str, purpose: str, purpose_source: str, policies: list):
    """Handle APK file upload."""
    if not apk_parser_available():
        raise HTTPException(
            status_code=422,
            detail="APK parsing requires Androguard. Install with: pip install androguard. "
                   "You can still analyze apps using manifest XML, JSON, or CSV input."
        )

    # Save to temp file
    temp_path = None
    try:
        temp_name = f"{uuid.uuid4().hex}_{filename}"
        temp_path = str(UPLOAD_DIR / temp_name)
        with open(temp_path, 'wb') as f:
            f.write(content)

        apk_result = parse_apk(temp_path, MAX_UPLOAD_SIZE_BYTES)

        suggested_purpose = infer_purpose(apk_result.app_name, apk_result.package_name)

        app_result = analyze_app(
            app_name=apk_result.app_name or apk_result.package_name or "Unknown App",
            package_name=apk_result.package_name,
            permissions=apk_result.permissions,
            purpose=purpose,
            purpose_source=purpose_source,
            input_source="apk",
            version=apk_result.version_name,
            target_sdk=apk_result.target_sdk,
            active_policies=policies,
            metadata={
                "min_sdk": apk_result.min_sdk,
                "version_code": apk_result.version_code,
                "has_foreground_service": apk_result.has_foreground_service,
                "parse_warnings": apk_result.parse_warnings,
                "suggested_purpose": suggested_purpose,
                "original_filename": filename,
            },
        )

        save_analysis(app_result)
        return app_result

    finally:
        # Clean up temp file
        if temp_path and DELETE_APK_AFTER_PARSE:
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning(f"Failed to clean up temp file: {temp_path}")


async def _handle_json_upload(content: bytes, purpose: str, purpose_source: str, policies: list):
    """Handle JSON report upload."""
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="JSON file must be UTF-8 encoded.")

    records = parse_json_report(text)
    results = []

    for record in records:
        final_purpose = record.purpose or purpose
        final_purpose_source = record.purpose_source if record.purpose else purpose_source

        app_result = analyze_app(
            app_name=record.app_name,
            package_name=record.package_name,
            permissions=record.permissions,
            purpose=final_purpose,
            purpose_source=final_purpose_source,
            input_source="json-report",
            version=record.version or "",
            target_sdk=record.target_sdk or "",
            active_policies=policies,
            metadata={"description": record.description, "source": record.source},
        )
        save_analysis(app_result)
        results.append(app_result)

    return {"analyzed": len(results), "results": results}


async def _handle_csv_upload(content: bytes, purpose: str, purpose_source: str, policies: list):
    """Handle CSV report upload."""
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        try:
            text = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="CSV file must be UTF-8 encoded.")

    records = parse_csv_report(text)
    results = []

    for record in records:
        final_purpose = record.purpose or purpose
        final_purpose_source = record.purpose_source if record.purpose else purpose_source

        app_result = analyze_app(
            app_name=record.app_name,
            package_name=record.package_name,
            permissions=record.permissions,
            purpose=final_purpose,
            purpose_source=final_purpose_source,
            input_source="csv-report",
            version=record.version or "",
            target_sdk=record.target_sdk or "",
            active_policies=policies,
            metadata={"description": record.description, "source": record.source},
        )
        save_analysis(app_result)
        results.append(app_result)

    return {"analyzed": len(results), "results": results}


@router.post("/api/analyze/infer-purpose")
async def infer_app_purpose(app_name: str = "", package_name: str = ""):
    """Suggest a purpose category based on app name/package keywords."""
    suggested = infer_purpose(app_name, package_name)
    return {
        "suggested_purpose": suggested,
        "is_inference": True,
        "note": "This is a keyword-based suggestion. Please verify and confirm the correct purpose.",
    }


# === Apps CRUD ===

@router.get("/api/apps")
async def list_apps():
    """List all analyzed apps."""
    analyses = get_all_analyses()
    return {"apps": analyses}


@router.get("/api/apps/{analysis_id}")
async def get_app_detail(analysis_id: str):
    """Get detailed analysis for a specific app."""
    detail = get_analysis_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return detail


@router.delete("/api/apps/{analysis_id}")
async def delete_app(analysis_id: str):
    """Delete an analysis."""
    deleted = delete_analysis(analysis_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {"deleted": True, "id": analysis_id}


@router.delete("/api/apps")
async def delete_all_apps():
    """Delete all analyses."""
    delete_all_analyses()
    return {"deleted": True, "message": "All analyses deleted."}


@router.put("/api/apps/{analysis_id}/notes")
async def update_notes(analysis_id: str, request: UpdateNotesRequest):
    """Update user notes for an analysis."""
    updated = update_user_notes(analysis_id, request.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {"updated": True}


# === Policies ===

@router.get("/api/policies")
async def list_policies():
    """List all custom policies."""
    policies = get_all_policies()
    return {"policies": policies}


@router.post("/api/policies")
async def create_policy(request: PolicyCreateRequest):
    """Create a new security policy."""
    policy = save_policy(request.model_dump())
    return policy


@router.put("/api/policies/{policy_id}")
async def update_policy(policy_id: str, request: PolicyUpdateRequest):
    """Update an existing security policy."""
    data = {k: v for k, v in request.model_dump().items() if v is not None}
    updated = save_policy(data, policy_id=policy_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return updated


@router.delete("/api/policies/{policy_id}")
async def delete_policy_route(policy_id: str):
    """Delete a security policy."""
    deleted = delete_policy(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found.")
    return {"deleted": True, "id": policy_id}


# === Exports ===

@router.get("/api/exports/apps.csv")
async def export_apps_csv():
    """Export summary of all analyzed apps as CSV."""
    analyses = get_all_analyses()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Package Name", "App Name", "Purpose", "Score",
        "Risk Band", "Input Source", "Created At"
    ])

    for a in analyses:
        writer.writerow([
            a.get("id", ""),
            a.get("package_name", ""),
            a.get("app_name", ""),
            a.get("selected_purpose", ""),
            a.get("score", 0),
            a.get("risk_band", ""),
            a.get("input_source", ""),
            a.get("created_at", ""),
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=permission_sentinel_apps.csv"}
    )


@router.get("/api/exports/{analysis_id}.json")
async def export_analysis_json(analysis_id: str):
    """Export single analysis detail as JSON."""
    detail = get_analysis_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    return JSONResponse(
        content=detail,
        headers={"Content-Disposition": f"attachment; filename={detail.get('package_name', 'analysis')}_report.json"}
    )


@router.get("/api/exports/{analysis_id}.csv")
async def export_analysis_csv(analysis_id: str):
    """Export permission findings for a single app as CSV."""
    detail = get_analysis_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Permission", "Label", "Status", "Severity", "Base Weight",
        "Reason", "Data Exposed", "Recommendation"
    ])

    for f in detail.get("permission_findings", []):
        writer.writerow([
            f.get("permission", ""),
            f.get("label", ""),
            f.get("status", ""),
            f.get("severity", ""),
            f.get("base_weight", 0),
            f.get("reason", ""),
            f.get("data_exposed", ""),
            f.get("recommendation", ""),
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={detail.get('package_name', 'analysis')}_findings.csv"}
    )
