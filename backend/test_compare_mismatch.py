import json
import urllib.request
import urllib.parse

url = 'http://localhost:8000/api/analyze/compare'

old_data = {
    "app_name": "App A",
    "package_name": "com.company.appA",
    "version": "1.0.0",
    "permissions": ["android.permission.INTERNET"]
}

new_data = {
    "app_name": "App B",
    "package_name": "com.company.appB",
    "version": "2.0.0",
    "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"]
}

data = urllib.parse.urlencode({
    'report_old_json': json.dumps(old_data),
    'report_new_json': json.dumps(new_data)
}).encode('utf-8')

req = urllib.request.Request(url, data=data)
try:
    with urllib.request.urlopen(req) as response:
        print('UNEXPECTED SUCCESS')
except urllib.error.HTTPError as e:
    print('HTTP ERROR:', e.code)
    print('ERROR DETAIL:', e.read().decode('utf-8'))
