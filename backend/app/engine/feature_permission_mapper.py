"""
Permission Sentinel - Feature Permission Mapper
Maps advertised features to expected Android permissions.
"""

from typing import Dict, List, Set, Any

FEATURE_TO_PERMISSIONS: Dict[str, Set[str]] = {
    "music_video_streaming": {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.WAKE_LOCK",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_VIDEO"
    },
    "camera_photo": {
        "android.permission.CAMERA",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    },
    "gps_navigation": {
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE"
    },
    "voice_search_recording": {
        "android.permission.RECORD_AUDIO",
        "android.permission.MICROPHONE"
    },
    "contact_sync": {
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS"
    },
    "bluetooth_nearby": {
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.ACCESS_LOCAL_NETWORK"
    },
    "messaging_notifications": {
        "android.permission.INTERNET",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.VIBRATE",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS"
    },
    "calendar_management": {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.SCHEDULE_EXACT_ALARM",
        "android.permission.USE_EXACT_ALARM"
    },
    "file_storage_sync": {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_IMAGES"
    }
}


def get_permissions_for_features(extracted_features: List[Dict[str, Any]]) -> Set[str]:
    """Return set of permission strings supported by extracted features."""
    supported: Set[str] = set()
    for feat in extracted_features:
        fid = feat.get("feature_id")
        if fid in FEATURE_TO_PERMISSIONS:
            supported.update(FEATURE_TO_PERMISSIONS[fid])
    return supported
