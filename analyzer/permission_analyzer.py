import json
import os

def load_permissions_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'dangerous_permissions.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def analyze_permissions(apk_obj, dvm_array):
    if not apk_obj:
        return {"permissions": [], "score": 0, "rate": 0}
        
    requested_perms = apk_obj.get_permissions()
    config = load_permissions_config()
    
    results = []
    total_score = 0
    
    for perm in requested_perms:
        perm_info = {"name": perm, "category": "NORMAL", "weight": 0}
        
        if perm in config:
            perm_info["category"] = config[perm]["category"]
            perm_info["weight"] = config[perm]["weight"]
            total_score += config[perm]["weight"]
        elif any(p in perm for p in config.keys()): # Fallback matching
            for k in config.keys():
                if k in perm:
                    perm_info["category"] = config[k]["category"]
                    perm_info["weight"] = config[k]["weight"]
                    total_score += config[k]["weight"]
                    break
        
        results.append(perm_info)
        
    num_classes = sum([len(vm.get_classes()) for vm in dvm_array]) if dvm_array else 1
    # Avoid div by 0 just in case
    rate = len(requested_perms) / max(num_classes, 1)
    
    return {
        "permissions": results,
        "score": total_score,
        "rate": rate,
        "total": len(requested_perms)
    }
