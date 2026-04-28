def analyze_opcodes(analysis_obj, enable_deep=False):
    if not analysis_obj or not enable_deep:
        return {"obfuscation_risk": False, "score": 0, "indicators": {}}
        
    suspicious_opcodes = ['invoke-runtime', 'filled-new-array', 'move-exception', 'aget-object']
    counts = {op: 0 for op in suspicious_opcodes}
    total_instructions = 0
    
    for method in analysis_obj.get_methods():
        if method.is_external():
            continue
        m = method.get_method()
        if not hasattr(m, 'get_code') or m.get_code() is None:
            continue
        try:
            for ins in method.get_instructions():
                total_instructions += 1
                op_name = ins.get_name()
                if isinstance(op_name, bytes):
                    op_name = op_name.decode('utf-8', errors='ignore')
                if op_name in counts:
                    counts[op_name] += 1
        except Exception:
            pass
            
    if total_instructions == 0:
        return {"obfuscation_risk": False, "score": 0, "indicators": counts}
        
    suspicious_freq = sum(counts.values()) / total_instructions
    obfuscation_risk = suspicious_freq > 0.12 # 12% heuristic
    
    return {
        "obfuscation_risk": obfuscation_risk,
        "score": 15 if obfuscation_risk else 0,
        "indicators": counts,
        "total_instructions": total_instructions
    }
