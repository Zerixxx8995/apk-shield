import json
import os

def load_trackers_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tracker_signatures.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def detect_trackers(dvm_array):
    if not dvm_array:
        return {"trackers": [], "score": 0}
        
    config = load_trackers_config()
    detected = []
    score = 0
    
    seen_prefixes = set()
    
    for vm in dvm_array:
        for classes in vm.get_classes():
            name = classes.get_name()
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore')
            # typical format: Lcom/google/firebase/Analytics;
            clean_name = name.replace('L', '', 1).replace(';', '').replace('/', '.')
            
            for tracker in config:
                prefix = tracker["package_prefix"]
                if clean_name.startswith(prefix) and prefix not in seen_prefixes:
                    seen_prefixes.add(prefix)
                    detected.append({
                        "name": tracker["name"],
                        "category": tracker["category"],
                        "risk_level": tracker["risk_level"]
                    })
                    if tracker["risk_level"] == "HIGH":
                        score += 10
                    elif tracker["risk_level"] == "MEDIUM":
                        score += 5
                    else:
                        score += 2
                        
    return {
        "trackers": detected,
        "score": score
    }
