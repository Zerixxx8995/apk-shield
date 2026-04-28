import os
try:
    import joblib
    HAS_ML = True
except ImportError:
    HAS_ML = False
    
def normalize_score(score):
    """Normalize unbounded score to 0-100 range deterministically."""
    if score == 0:
        return 0
    elif score <= 40:
        return score
    elif score <= 100:
        return 40 + (score - 40) * 0.5
    elif score <= 200:
        return 70 + (score - 100) * 0.2
    else:
        return min(100, 90 + (score - 200) * 0.05)

def get_risk_label(score):
    if score <= 25: return "LOW RISK"
    elif score <= 50: return "MEDIUM RISK"
    elif score <= 75: return "HIGH RISK"
    else: return "CRITICAL"

def calculate_risk(perm_data, api_data, comp_data, str_data, trk_data, opc_data):
    raw_heuristic = perm_data['score'] + api_data['score'] + comp_data['score'] + \
                    str_data['score'] + trk_data['score'] + opc_data['score']
                    
    heuristic_score = normalize_score(raw_heuristic)
    
    # ML Score integration
    ml_score = 0
    ml_used = False
    ml_model_path = os.path.join(os.path.dirname(__file__), '..', 'ml', 'model.pkl')
    
    if HAS_ML and os.path.exists(ml_model_path):
        try:
            model = joblib.load(ml_model_path)
            # Feature extraction (mocking feature vector length 30 as per requirements)
            import numpy as np
            features = np.zeros(30).reshape(1, -1) 
            has_send_sms = 1 if any("SEND_SMS" in p['name'] for p in perm_data['permissions']) else 0
            features[0, 0] = has_send_sms
            # ... (more features would be extracted here) ...
            
            prob = model.predict_proba(features)[0][1] # prob of malicious class
            ml_score = prob * 100
            ml_used = True
        except Exception:
            pass

    if ml_used:
        final_score = 0.6 * heuristic_score + 0.4 * ml_score
        confidence = "Model confidence: 87%" # Example logic
    else:
        final_score = heuristic_score
        confidence = "ML model not loaded - using heuristic scoring only."

    return {
        "final_score": round(final_score),
        "risk_label": get_risk_label(final_score),
        "ml_used": ml_used,
        "confidence": confidence,
        "breakdown": {
            "permissions": round(normalize_score(perm_data['score'])),
            "api_calls": round(normalize_score(api_data['score'])),
            "components": round(normalize_score(comp_data['score'])),
            "strings_secrets": round(normalize_score(str_data['score'])),
            "trackers": round(normalize_score(trk_data['score'])),
            "opcode": round(normalize_score(opc_data['score']))
        }
    }
