from llm_utils import get_llm_judgement_from_file
from fastapi import UploadFile

async def analyze(file: UploadFile):
    # Validate file
    if not file.filename:
        return {
            "type": "image",
            "error": "No file provided"
        }
    
    # Check content type
    content_type = file.content_type or ""
    if not content_type.startswith('image/'):
        return {
            "type": "image",
            "filename": file.filename,
            "error": f"Invalid file type: {content_type}. Expected image file."
        }
    
    # Read file to check size and validate
    file_data = await file.read()
    await file.seek(0)  # Reset for further processing
    
    if len(file_data) < 10:
        return {
            "type": "image",
            "filename": file.filename,
            "error": "Invalid or empty image data"
        }
    
    # Validate image format by file signature
    valid_format = False
    detected_type = content_type
    
    # PNG: starts with 89 50 4E 47 0D 0A 1A 0A
    if file_data.startswith(b'\x89PNG\r\n\x1a\n'):
        valid_format = True
        detected_type = "image/png"
    # JPEG: starts with FF D8 and ends with FF D9
    elif file_data.startswith(b'\xFF\xD8') and file_data.endswith(b'\xFF\xD9'):
        valid_format = True
        detected_type = "image/jpeg"
    # GIF: starts with GIF87a or GIF89a
    elif file_data.startswith(b'GIF87a') or file_data.startswith(b'GIF89a'):
        valid_format = True
        detected_type = "image/gif"
    # WebP: starts with RIFF and contains WEBP
    elif file_data.startswith(b'RIFF') and b'WEBP' in file_data[:20]:
        valid_format = True
        detected_type = "image/webp"
    
    if not valid_format:
        return {
            "type": "image",
            "filename": file.filename,
            "size_bytes": len(file_data),
            "error": "Unsupported or corrupted image format. Only PNG, JPEG, GIF, and WebP are supported."
        }
    
    # Send image file directly to LLM for analysis
    judgement = await get_llm_judgement_from_file(file)
    
    return {
        "type": "image", 
        "filename": file.filename,
        "size_bytes": len(file_data), 
        "media_type": detected_type,
        "judgement": judgement
    }
