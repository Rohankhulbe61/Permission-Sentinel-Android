"""
Permission Sentinel - Metadata Service
Retrieves and caches public Google Play Store app metadata safely.
Handles network timeouts, 404s, regional restrictions, and parsing errors.
"""

import json
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from app.config import DATA_DIR

CACHE_FILE = DATA_DIR / "metadata_cache.json"
_memory_cache: Dict[str, Any] = {}


def _load_cache() -> Dict[str, Any]:
    global _memory_cache
    if _memory_cache:
        return _memory_cache

    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                _memory_cache = json.load(f)
        except Exception:
            _memory_cache = {}
    return _memory_cache


def _save_cache() -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_memory_cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def get_play_store_metadata(package_name: str, app_name_hint: str = "") -> Dict[str, Any]:
    """
    Retrieve metadata for a package name from Google Play Store or local cache.
    Never crashes or blocks on network failures. Always returns a valid dict.
    """
    if not package_name or package_name.strip() == "":
        return _build_fallback_metadata(package_name, app_name_hint)

    pkg = package_name.strip()
    cache = _load_cache()

    if pkg in cache:
        return cache[pkg]

    url = f"https://play.google.com/store/apps/details?id={pkg}&hl=en&gl=US"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        metadata = _parse_play_store_html(html, pkg, app_name_hint)
        _memory_cache[pkg] = metadata
        _save_cache()
        return metadata

    except (urllib.error.HTTPError, urllib.error.URLError, Exception):
        fallback = _build_fallback_metadata(pkg, app_name_hint)
        _memory_cache[pkg] = fallback
        _save_cache()
        return fallback


def _parse_play_store_html(html: str, package_name: str, app_name_hint: str) -> Dict[str, Any]:
    """Extract metadata fields from public Play Store HTML using regex."""
    title_match = re.search(r'<h1[^>]*itemprop="name"[^>]*>(.*?)</h1>', html, re.DOTALL | re.IGNORECASE)
    if not title_match:
        title_match = re.search(r'<title>(.*?) - Apps on Google Play</title>', html, re.IGNORECASE)
    extracted_title = title_match.group(1).strip() if title_match else (app_name_hint or package_name)
    extracted_title = re.sub(r'<[^>]+>', '', extracted_title).strip()

    category_match = re.search(r'itemprop="genre"[^>]*>(.*?)</span>', html, re.DOTALL | re.IGNORECASE)
    if not category_match:
        category_match = re.search(r'/store/apps/category/([^"?]+)', html, re.IGNORECASE)
    category = category_match.group(1).strip() if category_match else "General"
    category = re.sub(r'<[^>]+>', '', category).replace("_", " ").title()

    dev_match = re.search(r'href="/store/apps/developer\?id=[^"]*"[^>]*>(.*?)</a>', html, re.DOTALL | re.IGNORECASE)
    developer = dev_match.group(1).strip() if dev_match else "Unknown Developer"
    developer = re.sub(r'<[^>]+>', '', developer).strip()

    desc_match = re.search(r'<div[^>]*itemprop="description"[^>]*>(.*?)</div>', html, re.DOTALL | re.IGNORECASE)
    if not desc_match:
        desc_match = re.search(r'<meta[^>]*name="description"[^>]*content="([^"]*)"', html, re.IGNORECASE)
    raw_desc = desc_match.group(1).strip() if desc_match else ""
    clean_desc = re.sub(r'<[^>]+>', ' ', raw_desc).strip()

    return {
        "package_name": package_name,
        "app_name": extracted_title,
        "developer": developer,
        "play_category": category,
        "description": clean_desc[:4000],
        "has_listing": True,
        "metadata_source": "Google Play Store",
        "listing_url": f"https://play.google.com/store/apps/details?id={package_name}",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def _build_fallback_metadata(package_name: str, app_name_hint: str) -> Dict[str, Any]:
    """Fallback metadata when Play Store listing is missing or inaccessible."""
    return {
        "package_name": package_name,
        "app_name": app_name_hint or package_name,
        "developer": "Local Device App",
        "play_category": "General",
        "description": "",
        "has_listing": False,
        "metadata_source": "Device Scan (No Play Store Listing)",
        "listing_url": f"https://play.google.com/store/apps/details?id={package_name}",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
