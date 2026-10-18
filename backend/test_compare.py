import json
import urllib.request
import urllib.parse

url = 'http://localhost:8000/api/analyze/compare'

old_data = {
    "app_name": "Flashlight Calc",
    "package_name": "com.utility.flashlight",
    "version": "1.0.0",
    "purpose": "Calculator / Simple Utility",
    "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]
}

new_data = {
    "app_name": "Flashlight Calc",
    "package_name": "com.utility.flashlight",
    "version": "2.0.0",
    "purpose": "Calculator / Simple Utility",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO"
    ]
}

data = urllib.parse.urlencode({
    'report_old_json': json.dumps(old_data),
    'report_new_json': json.dumps(new_data),
    'purpose': 'Calculator / Simple Utility'
}).encode('utf-8')

req = urllib.request.Request(url, data=data)
try:
    with urllib.request.urlopen(req) as response:
        body = response.read().decode('utf-8')
        print('STATUS: 200')
        print('JSON OUTPUT:')
        print(json.dumps(json.loads(body), indent=2))
except urllib.error.HTTPError as e:
    print('HTTP ERROR:', e.code, e.read().decode('utf-8'))
