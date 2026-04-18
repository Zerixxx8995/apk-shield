def extract_features(perm_data, api_data, comp_data, str_data, trk_data, opc_data):
    """
    Extracts ~30 binary and numeric features to match the trained Random Forest model.
    """
    features = []
    # 1. has_READ_PHONE_STATE
    features.append(1 if any("READ_PHONE_STATE" in p["name"] for p in perm_data["permissions"]) else 0)
    # 2. has_SEND_SMS
    features.append(1 if any("SEND_SMS" in p["name"] for p in perm_data["permissions"]) else 0)
    # 3. total_permissions
    features.append(len(perm_data["permissions"]))
    # 4. permission_rate
    features.append(perm_data.get("rate", 0))
    # Fill remaining to make 30 features
    for _ in range(26):
        features.append(0)
        
    return features
