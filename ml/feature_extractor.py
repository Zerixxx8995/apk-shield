"""
Feature extractor for the Random Forest malware classifier.

Builds a 40-element binary feature vector matching the DREBIN-trained model:
  - 25 permission flags
  - 14 API/callback flags
  - 1 intent flag (BOOT_COMPLETED)

Supports two extraction paths:
  1. Direct APK/analysis objects (androguard) — highest fidelity
  2. Fallback to heuristic analyzer report dicts — used when objects unavailable
"""

import numpy as np

# Feature list — must match train_model.py exactly, in the same order.
FEATURES = [
    # 25 Permissions
    "SEND_SMS",
    "READ_PHONE_STATE",
    "RECEIVE_SMS",
    "READ_SMS",
    "WRITE_SMS",
    "GET_ACCOUNTS",
    "CAMERA",
    "INTERNET",
    "RECORD_AUDIO",
    "NFC",
    "WAKE_LOCK",
    "RECEIVE_BOOT_COMPLETED",
    "RESTART_PACKAGES",
    "BLUETOOTH",
    "READ_CALENDAR",
    "READ_CALL_LOG",
    "READ_EXTERNAL_STORAGE",
    "VIBRATE",
    "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE",
    "WRITE_EXTERNAL_STORAGE",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "SYSTEM_ALERT_WINDOW",
    "DISABLE_KEYGUARD",
    # 14 APIs & Callbacks
    "transact",
    "onServiceConnected",
    "bindService",
    "ClassLoader",
    "DexClassLoader",
    "PathClassLoader",
    "Runtime.getRuntime",
    "Runtime.exec",
    "System.loadLibrary",
    "Ljavax.crypto.Cipher",
    "TelephonyManager.getDeviceId",
    "TelephonyManager.getSubscriberId",
    "TelephonyManager.getLine1Number",
    "TelephonyManager.getSimSerialNumber",
    # 1 Intent
    "android.intent.action.BOOT_COMPLETED",
]

_PERM_FEATURES = FEATURES[:25]
_API_FEATURES = FEATURES[25:39]
_INTENT_FEATURE = FEATURES[39]  # "android.intent.action.BOOT_COMPLETED"


def _extract_from_objects(features_dict, apk_obj, analysis_obj):
    """Extract features directly from androguard APK / analysis objects."""

    # --- Permissions ---
    if apk_obj:
        try:
            requested_perms = apk_obj.get_permissions()
            for perm in _PERM_FEATURES:
                full_name = f"android.permission.{perm}"
                if full_name in requested_perms or perm in requested_perms:
                    features_dict[perm] = 1
        except Exception:
            pass

        # --- Intent (BOOT_COMPLETED from manifest) ---
        try:
            manifest_xml = apk_obj.get_android_manifest_xml()
            if manifest_xml is not None:
                for action in manifest_xml.findall('.//action'):
                    action_name = action.get(
                        '{http://schemas.android.com/apk/res/android}name', ''
                    )
                    if 'BOOT_COMPLETED' in action_name:
                        features_dict[_INTENT_FEATURE] = 1
                        break
        except Exception:
            pass

    # --- APIs & Callbacks ---
    if analysis_obj:
        try:
            for method in analysis_obj.get_methods():
                m = method.get_method()
                method_name = m.get_name()
                class_name = m.get_class_name()
                if isinstance(method_name, bytes):
                    method_name = method_name.decode('utf-8', errors='ignore')
                if isinstance(class_name, bytes):
                    class_name = class_name.decode('utf-8', errors='ignore')

                normalized_class = class_name.replace('/', '.')

                if method_name == "transact":
                    features_dict["transact"] = 1
                if method_name == "onServiceConnected":
                    features_dict["onServiceConnected"] = 1
                if method_name == "bindService":
                    features_dict["bindService"] = 1
                if "ClassLoader" in normalized_class:
                    features_dict["ClassLoader"] = 1
                if "DexClassLoader" in normalized_class:
                    features_dict["DexClassLoader"] = 1
                if "PathClassLoader" in normalized_class:
                    features_dict["PathClassLoader"] = 1
                if method_name == "getRuntime" and "Runtime" in normalized_class:
                    features_dict["Runtime.getRuntime"] = 1
                if method_name == "exec" and "Runtime" in normalized_class:
                    features_dict["Runtime.exec"] = 1
                if method_name == "loadLibrary" and "System" in normalized_class:
                    features_dict["System.loadLibrary"] = 1
                if "Cipher" in normalized_class:
                    features_dict["Ljavax.crypto.Cipher"] = 1
                if method_name == "getDeviceId" and "TelephonyManager" in normalized_class:
                    features_dict["TelephonyManager.getDeviceId"] = 1
                if method_name == "getSubscriberId" and "TelephonyManager" in normalized_class:
                    features_dict["TelephonyManager.getSubscriberId"] = 1
                if method_name == "getLine1Number" and "TelephonyManager" in normalized_class:
                    features_dict["TelephonyManager.getLine1Number"] = 1
                if method_name == "getSimSerialNumber" and "TelephonyManager" in normalized_class:
                    features_dict["TelephonyManager.getSimSerialNumber"] = 1
        except Exception:
            pass


def _extract_from_reports(features_dict, perm_data, api_data, comp_data):
    """Fallback: extract features from the heuristic analyzer report dicts."""

    # --- Permissions ---
    if perm_data and 'permissions' in perm_data:
        try:
            extracted_names = [p['name'] for p in perm_data['permissions']]
            for perm in _PERM_FEATURES:
                full_name = f"android.permission.{perm}"
                if any(full_name in name or perm in name for name in extracted_names):
                    features_dict[perm] = 1
        except Exception:
            pass

    # --- Intent (BOOT_COMPLETED via component patterns) ---
    if comp_data and 'patterns' in comp_data:
        try:
            if any(p.get('tag') == 'Persistence' for p in comp_data['patterns']):
                features_dict[_INTENT_FEATURE] = 1
        except Exception:
            pass

    # --- APIs & Callbacks ---
    if api_data and 'apis' in api_data:
        try:
            extracted_apis = [a['method'] for a in api_data['apis']]
            extracted_classes = [a['class'] for a in api_data['apis']]

            for api in extracted_apis:
                if api == "transact":
                    features_dict["transact"] = 1
                if api == "onServiceConnected":
                    features_dict["onServiceConnected"] = 1
                if api == "bindService":
                    features_dict["bindService"] = 1
                if api == "getRuntime":
                    features_dict["Runtime.getRuntime"] = 1
                if api == "exec":
                    features_dict["Runtime.exec"] = 1
                if api == "loadLibrary":
                    features_dict["System.loadLibrary"] = 1
                if api == "getDeviceId":
                    features_dict["TelephonyManager.getDeviceId"] = 1
                if api == "getSubscriberId":
                    features_dict["TelephonyManager.getSubscriberId"] = 1
                if api == "getLine1Number":
                    features_dict["TelephonyManager.getLine1Number"] = 1
                if api == "getSimSerialNumber":
                    features_dict["TelephonyManager.getSimSerialNumber"] = 1

            for cls in extracted_classes:
                normalized = cls.replace('/', '.')
                if "ClassLoader" in normalized:
                    features_dict["ClassLoader"] = 1
                if "DexClassLoader" in normalized:
                    features_dict["DexClassLoader"] = 1
                if "PathClassLoader" in normalized:
                    features_dict["PathClassLoader"] = 1
                if "Cipher" in normalized:
                    features_dict["Ljavax.crypto.Cipher"] = 1
        except Exception:
            pass


def extract_features(perm_data, api_data, comp_data, str_data, trk_data, opc_data,
                     apk_obj=None, analysis_obj=None):
    """
    Build the full 40-element numpy feature vector for the trained model.

    Uses androguard objects when available (highest fidelity), otherwise
    falls back to the heuristic analyzer report dicts.

    Returns:
        numpy.ndarray of shape (1, 40) — ready for model.predict().
    """
    features_dict = {f: 0 for f in FEATURES}

    if apk_obj or analysis_obj:
        _extract_from_objects(features_dict, apk_obj, analysis_obj)
    else:
        _extract_from_reports(features_dict, perm_data, api_data, comp_data)

    feat_list = [features_dict[f] for f in FEATURES]
    return np.array(feat_list).reshape(1, -1)
