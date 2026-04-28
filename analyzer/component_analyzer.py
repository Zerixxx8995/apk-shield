def analyze_components(apk_obj):
    if not apk_obj:
        return {"patterns": [], "score": 0}
        
    activities = apk_obj.get_activities()
    services = apk_obj.get_services()
    receivers = apk_obj.get_receivers()
    
    # We will look at combinations of intents and components
    patterns = []
    score = 0
    
    manifest_xml = None
    try:
        manifest_xml = apk_obj.get_android_manifest_xml()
    except Exception:
        pass

    has_boot_completed_receiver = False
    has_sms_received_receiver = False
    
    if manifest_xml is not None:
        for receiver in manifest_xml.findall('.//receiver'):
            for intent in receiver.findall('.//action'):
                action_name = intent.get('{http://schemas.android.com/apk/res/android}name', '')
                if 'BOOT_COMPLETED' in action_name:
                    has_boot_completed_receiver = True
                if 'SMS_RECEIVED' in action_name:
                    has_sms_received_receiver = True
                    
    requested_perms = apk_obj.get_permissions()
    
    if has_boot_completed_receiver and len(services) > 0:
        patterns.append({
            "tag": "Persistence",
            "desc": "Found RECEIVE_BOOT_COMPLETED coupled with Background Services",
            "severity": "MEDIUM"
        })
        score += 8
        
    if has_sms_received_receiver and any("SEND_SMS" in p for p in requested_perms):
        patterns.append({
            "tag": "SMS Hijacking pattern",
            "desc": "Listens for SMS and has permission to Send SMS",
            "severity": "CRITICAL"
        })
        score += 25
        
    if any("READ_CONTACTS" in p for p in requested_perms) and any("INTERNET" in p for p in requested_perms):
        patterns.append({
            "tag": "Data exfiltration pattern",
            "desc": "READ_CONTACTS combined with INTERNET access",
            "severity": "HIGH"
        })
        score += 15
        
    if any("REQUEST_INSTALL_PACKAGES" in p for p in requested_perms):
        patterns.append({
            "tag": "Dropper malware pattern",
            "desc": "App can request silent installation of other packages",
            "severity": "CRITICAL"
        })
        score += 20

    return {
        "patterns": patterns,
        "score": score
    }
