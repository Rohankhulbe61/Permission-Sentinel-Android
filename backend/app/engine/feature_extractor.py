"""
Permission Sentinel - Feature Extractor
Extracts advertised functionality and capabilities from application description text.
Includes synonym mapping, phrase matching, and confidence assessment.
"""

import re
from typing import List, Dict, Any

FEATURE_DICTIONARY: Dict[str, Dict[str, Any]] = {
    "music_video_streaming": {
        "label": "Music & Video Streaming",
        "keywords": ["music", "stream", "songs", "playlist", "audio", "video", "podcast", "listen", "vlog", "media player"],
        "patterns": [r"listen to (music|songs|podcasts|playlists)", r"watch (videos|streams|vlogs)", r"stream (audio|video|music)"],
    },
    "camera_photo": {
        "label": "Camera Capture & Photo Editing",
        "keywords": ["camera", "photo", "picture", "take photos", "record video", "gallery", "image editor", "snap", "lens"],
        "patterns": [r"take (photos|pictures|videos)", r"camera (filters|effects|capture)", r"photo (editing|editor|gallery)"],
    },
    "gps_navigation": {
        "label": "GPS Navigation & Location Services",
        "keywords": ["navigation", "map", "maps", "gps", "directions", "turn-by-turn", "location", "navigate", "route", "places nearby"],
        "patterns": [r"turn-by-turn (navigation|directions)", r"gps (location|tracking|navigation)", r"find (nearby|places|routes)"],
    },
    "voice_search_recording": {
        "label": "Voice Search & Audio Recording",
        "keywords": ["voice search", "microphone", "record audio", "voice commands", "voice note", "speech recognition"],
        "patterns": [r"voice (search|commands|input|notes)", r"record (audio|voice|conversations)", r"speech (to text|recognition)"],
    },
    "contact_sync": {
        "label": "Contact Synchronization & Address Book",
        "keywords": ["contacts", "address book", "friends list", "sync contacts", "phonebook", "invite friends"],
        "patterns": [r"(sync|import|find) (contacts|friends)", r"access (your contacts|address book)"],
    },
    "bluetooth_nearby": {
        "label": "Bluetooth & Nearby Device Connectivity",
        "keywords": ["bluetooth", "wireless headphones", "cast", "chromecast", "nearby devices", "connect devices", "smart home"],
        "patterns": [r"connect to (bluetooth|headphones|speakers|devices)", r"cast to (tv|chromecast|screen)"],
    },
    "messaging_notifications": {
        "label": "Messaging & Instant Notifications",
        "keywords": ["message", "messages", "chat", "notifications", "alerts", "sms", "inbox", "push notifications"],
        "patterns": [r"send (messages|sms|chats)", r"receive (notifications|alerts)", r"chat with (friends|users)"],
    },
    "calendar_management": {
        "label": "Calendar & Event Scheduling",
        "keywords": ["calendar", "events", "schedule", "reminders", "appointments", "planner", "agenda"],
        "patterns": [r"schedule (events|meetings|appointments)", r"calendar (planner|reminders|events)"],
    },
    "file_storage_sync": {
        "label": "File Storage & Offline Downloads",
        "keywords": ["download", "offline access", "save files", "storage", "cloud sync", "export", "backup"],
        "patterns": [r"download (songs|videos|files) for offline", r"save to (storage|device|sd card)"],
    }
}


def extract_advertised_features(description: str, app_name: str = "", package_name: str = "") -> List[Dict[str, Any]]:
    """
    Scan app description, title, and package name to extract advertised capabilities.
    Returns a list of feature dicts with supporting phrases and confidence levels.
    """
    text = f"{app_name} {package_name} {description}".lower()
    extracted: List[Dict[str, Any]] = []

    for feature_id, feature_info in FEATURE_DICTIONARY.items():
        matched_phrase = ""
        confidence = "medium"

        # Check regex patterns first (highest confidence)
        for pattern in feature_info["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_phrase = f"Matched phrase: '{match.group(0)}'"
                confidence = "high"
                break

        # Check keywords if no regex match
        if not matched_phrase:
            kw_hits = [kw for kw in feature_info["keywords"] if kw in text]
            if len(kw_hits) >= 2:
                matched_phrase = f"Matched terms: {', '.join(kw_hits[:3])}"
                confidence = "high" if len(kw_hits) >= 3 else "medium"
            elif len(kw_hits) == 1:
                matched_phrase = f"Matched term: '{kw_hits[0]}'"
                confidence = "medium"

        if matched_phrase:
            extracted.append({
                "feature_id": feature_id,
                "label": feature_info["label"],
                "evidence_phrase": matched_phrase,
                "confidence": confidence
            })

    return extracted
