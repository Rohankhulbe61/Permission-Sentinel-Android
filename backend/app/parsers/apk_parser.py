"""
Permission Sentinel - APK Parser
Uses Androguard to extract permissions and metadata from APK files.
Isolated behind a service boundary. Falls back gracefully if Androguard is not installed.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

ANDROGUARD_AVAILABLE = False
try:
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    logger.warning(
        "Androguard is not installed. APK parsing will not be available. "
        "Install with: pip install androguard"
    )


class APKParseError(Exception):
    """Raised when APK parsing fails."""
    pass


class APKParseResult:
    """Result of parsing an APK file."""
    def __init__(self):
        self.package_name: str = ""
        self.app_name: str = ""
        self.version_name: str = ""
        self.version_code: str = ""
        self.target_sdk: str = ""
        self.min_sdk: str = ""
        self.permissions: list[str] = []
        self.has_foreground_service: bool = False
        self.parse_warnings: list[str] = []


def is_available() -> bool:
    """Check if APK parsing is available (Androguard installed)."""
    return ANDROGUARD_AVAILABLE


def validate_apk_file(file_path: str, max_size_bytes: int) -> None:
    """
    Validate an APK file before parsing.
    
    Checks:
    - File exists
    - File size within limits
    - Basic file signature (PK zip header)
    """
    if not os.path.exists(file_path):
        raise APKParseError("APK file not found.")
    
    file_size = os.path.getsize(file_path)
    if file_size > max_size_bytes:
        raise APKParseError(
            f"APK file size ({file_size / (1024*1024):.1f} MB) exceeds the maximum "
            f"allowed size ({max_size_bytes / (1024*1024):.0f} MB)."
        )
    
    if file_size < 100:
        raise APKParseError("File is too small to be a valid APK.")
    
    # Check ZIP/PK signature
    with open(file_path, 'rb') as f:
        header = f.read(4)
    
    if header[:2] != b'PK':
        raise APKParseError(
            "Invalid APK file: missing ZIP signature. "
            "APK files are ZIP archives and must start with the PK header."
        )


def parse_apk(file_path: str, max_size_bytes: int) -> APKParseResult:
    """
    Parse an APK file and extract permissions and metadata.
    
    Args:
        file_path: Path to the APK file
        max_size_bytes: Maximum allowed file size
        
    Returns:
        APKParseResult with extracted data
        
    Raises:
        APKParseError: If parsing fails or Androguard is not available
    """
    if not ANDROGUARD_AVAILABLE:
        raise APKParseError(
            "APK parsing requires Androguard. Install with: pip install androguard. "
            "You can still analyze apps using manifest XML, JSON, or CSV input."
        )
    
    validate_apk_file(file_path, max_size_bytes)
    
    result = APKParseResult()
    
    try:
        apk = APK(file_path)
    except Exception as e:
        raise APKParseError(f"Failed to parse APK: {str(e)}")
    
    if not apk.is_valid_APK():
        raise APKParseError("The file is not a valid APK.")
    
    result.package_name = apk.get_package() or ""
    result.app_name = apk.get_app_name() or ""
    result.version_name = apk.get_androidversion_name() or ""
    result.version_code = apk.get_androidversion_code() or ""
    result.target_sdk = apk.get_target_sdk_version() or ""
    result.min_sdk = apk.get_min_sdk_version() or ""
    
    # Extract permissions (deduplicated)
    permissions = set()
    for perm in apk.get_permissions():
        perm = perm.strip()
        if perm:
            permissions.add(perm)
    
    result.permissions = sorted(permissions)
    
    if not result.permissions:
        result.parse_warnings.append(
            "No permissions found in the APK. The app may not require any permissions."
        )
    
    return result
