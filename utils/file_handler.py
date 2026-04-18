import os
import tempfile
import uuid

def save_uploaded_file(uploaded_file):
    try:
        temp_dir = tempfile.gettempdir()
        unique_filename = f"{uuid.uuid4()}_{uploaded_file.name}"
        file_path = os.path.join(temp_dir, unique_filename)
        
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        print(f"Error saving file: {e}")
        return None

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"Error deleting file: {e}")
