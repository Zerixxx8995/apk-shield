import re
import requests

def analyze_strings(dvm_array, apk_obj, check_headers=False):
    if not dvm_array:
        return {"urls": [], "secrets": [], "ips": [], "score": 0}
        
    package_name = apk_obj.get_package() if apk_obj else ""
    
    # Regex Patterns
    url_pattern = re.compile(r'https?://[^\s"\'<>]+')
    ip_pattern = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')
    google_key_pattern = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
    aws_key_pattern = re.compile(r'AKIA[0-9A-Z]{16}')
    firebase_pattern = re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com')
    private_key_pattern = re.compile(r'-----BEGIN (RSA|EC) PRIVATE KEY-----')
    
    urls = set()
    ips = set()
    secrets = []
    
    score = 0
    
    for vm in dvm_array:
        for string_value in vm.get_strings():
            if isinstance(string_value, bytes):
                string_value = string_value.decode('utf-8', errors='ignore')
            # URLs
            for match in url_pattern.finditer(string_value):
                urls.add(match.group())
            # IPs
            for match in ip_pattern.finditer(string_value):
                ips.add(match.group())
            # Secrets
            if google_key_pattern.search(string_value):
                secrets.append({"type": "Google API Key", "value": string_value, "redacted": string_value[:6] + "********"})
                score += 10
            if aws_key_pattern.search(string_value):
                secrets.append({"type": "AWS Key", "value": string_value, "redacted": string_value[:6] + "********"})
                score += 20
            if firebase_pattern.search(string_value):
                secrets.append({"type": "Firebase URL", "value": string_value, "redacted": string_value[:15] + "********"})
                score += 10
            if private_key_pattern.search(string_value):
                secrets.append({"type": "Private Key", "value": "Found RSA/EC Key", "redacted": "-----BEGIN PRIVATE KEY-----****"})
                score += 30

    url_list = []
    for u in urls:
        u_type = "Internal" if package_name and package_name.split('.')[-1] in u else "External"
        headers_status = "Skipped"
        if check_headers and u.startswith("http"):
            try:
                resp = requests.head(u, timeout=2)
                h = resp.headers
                missing = []
                if 'X-XSS-Protection' not in h: missing.append('XSS')
                if 'Strict-Transport-Security' not in h: missing.append('HSTS')
                if 'Content-Security-Policy' not in h: missing.append('CSP')
                headers_status = f"Missing: {', '.join(missing)}" if missing else "Secure"
            except:
                headers_status = "Unreachable"

        url_list.append({"url": u, "type": u_type, "headers": headers_status})
        
    return {
        "urls": url_list,
        "ips": list(ips),
        "secrets": secrets,
        "score": score
    }
