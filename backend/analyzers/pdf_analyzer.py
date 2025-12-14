import fitz  # PyMuPDF
from llm_utils import get_llm_judgement
from fastapi import UploadFile

async def analyze(file: UploadFile):
    # Validate file
    if not file.filename:
        return {
            "type": "pdf",
            "error": "No file provided"
        }
    
    # Check content type
    content_type = file.content_type or ""
    if content_type != "application/pdf" and not file.filename.lower().endswith('.pdf'):
        return {
            "type": "pdf",
            "filename": file.filename,
            "error": f"Invalid file type: {content_type}. Expected PDF file."
        }
    
    # Read PDF data
    pdf_data = await file.read()
    
    try:
        doc = fitz.open(stream=pdf_data, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        
        if not text.strip():
            return {
                "type": "pdf",
                "filename": file.filename,
                "size_bytes": len(pdf_data),
                "error": "No text content found in PDF"
            }
        
        judgement = get_llm_judgement(content=text)
        return {
            "type": "pdf", 
            "filename": file.filename,
            "size_bytes": len(pdf_data),
            "extracted_text_length": len(text),
            "judgement": judgement
        }
    except Exception as e:
        return {
            "type": "pdf",
            "filename": file.filename,
            "size_bytes": len(pdf_data),
            "error": f"Error processing PDF: {str(e)}"
        }
