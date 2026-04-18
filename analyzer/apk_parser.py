import hashlib
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

def parse_apk(file_path):
    """
    Parses the APK using Androguard. Returns apk_obj, dvm_array, analysis_obj, and basics.
    """
    try:
        a = APK(file_path)
        d = [DalvikVMFormat(dex) for dex in a.get_all_dex()]
        dx = Analysis()
        for vm in d:
            dx.add(vm)
        dx.create_xref()
        
        # Calculate SHA256
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                
        basics = {
            "app_name": a.get_app_name(),
            "package_name": a.get_package(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "sha256": sha256_hash.hexdigest(),
        }
        
        return a, d, dx, basics
    except Exception as e:
        print(f"Error parsing APK: {e}")
        return None, None, None, {"error": str(e)}
