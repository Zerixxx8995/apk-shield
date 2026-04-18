import json
import os

def load_apis_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'suspicious_apis.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def analyze_api_calls(analysis_obj):
    if not analysis_obj:
        return {"apis": [], "score": 0}
        
    config = load_apis_config()
    flagged_apis = []
    total_score = 0
    
    # We will track seen (method, class) to avoid huge duplicates
    seen = set()
    
    for method in analysis_obj.get_methods():
        method_name = method.get_method().get_name()
        class_name = method.get_method().get_class_name()
        
        if isinstance(method_name, bytes):
            method_name = method_name.decode('utf-8', errors='ignore')
        if isinstance(class_name, bytes):
            class_name = class_name.decode('utf-8', errors='ignore')
        
        # Check against config
        for api_conf in config:
            if api_conf["api"] in method_name:
                sig = (method_name, class_name)
                if sig not in seen:
                    seen.add(sig)
                    flagged_apis.append({
                        "method": method_name,
                        "class": class_name,
                        "risk_level": api_conf["risk_level"],
                        "points": api_conf["points"]
                    })
                    total_score += api_conf["points"]
                    
    return {
        "apis": flagged_apis,
        "score": total_score
    }
