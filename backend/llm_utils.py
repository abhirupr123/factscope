# llm_utils.py
import boto3
import json
from config import AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_KEY, TEXT_MODEL_ID, MULTIMODAL_MODEL_ID, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE

# Initialize Bedrock client
bedrock_client = boto3.client(
    service_name="bedrock-runtime",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

import base64
from fastapi import UploadFile

async def get_llm_judgement_from_file(file: UploadFile, additional_text: str = None) -> str:
    """
    Helper function to analyze UploadFile objects with LLM
    """
    # Read file data
    file_data = await file.read()
    
    # Reset file pointer for potential future reads
    await file.seek(0)
    
    # Determine content type
    content_type = file.content_type or "application/octet-stream"
    
    # Call the main function
    return get_llm_judgement(content=additional_text, media_data=file_data, media_type=content_type)

def get_llm_judgement(content: str = None, media_data: bytes = None, media_type: str = None) -> str:
    """
    Sends the input content (text and/or media) to AWS Bedrock LLM (e.g., Claude) and gets
    a plain-English explanation of whether it's fake/spam/AI-generated.
    
    Automatically selects the appropriate model:
    - Text-only: Uses faster, cheaper text model (Claude 3 Haiku)
    - With media: Uses multimodal model (Claude 3.5 Sonnet)
    
    Args:
        content: Text content to analyze
        media_data: Raw bytes of media file (image, etc.)
        media_type: Type of media ('image/jpeg', 'image/png', etc.)
    """
    try:
        # Build the message content array
        message_content = []
        
        # Add text content if provided
        if content:
            message_content.append({
                "type": "text",
                "text": f"Analyze the following content and explain in simple English whether it's fake, spam, or AI-generated, and why:\n\n{content}"
            })
        
        # Add media content if provided
        if media_data and media_type:
            # Validate image format and size
            if media_type.startswith('image/'):
                # Check if media type is supported by Claude
                supported_formats = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
                if media_type not in supported_formats:
                    return f"Unsupported image format: {media_type}. Supported formats: {', '.join(supported_formats)}"
                
                # Check image size (Claude has limits)
                max_size = 5 * 1024 * 1024  # 5MB limit
                if len(media_data) > max_size:
                    return f"Image too large: {len(media_data)} bytes. Maximum size: {max_size} bytes (5MB)"
                
                # Validate image data
                if len(media_data) < 100:  # Minimum viable image size
                    return "Image data too small or corrupted"
                
                try:
                    # Encode media data to base64
                    media_base64 = base64.b64encode(media_data).decode('utf-8')
                    
                    message_content.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": media_base64
                        }
                    })
                    
                    # Add analysis instruction for media
                    if not content:  # If no text content, add instruction for media analysis
                        message_content.insert(0, {
                            "type": "text",
                            "text": "Analyze the following image and explain in simple English whether it's fake, manipulated, AI-generated, or authentic, and why. Look for signs of digital manipulation, deepfakes, or artificial generation."
                        })
                        
                except Exception as e:
                    return f"Error encoding image data: {str(e)}"
            else:
                return f"Unsupported media type: {media_type}. Currently only image types are supported."
        
        # If no content provided at all, return error
        if not message_content:
            return "No content provided for analysis."
        
        # Determine which model to use based on content type
        has_media = media_data is not None and media_type is not None
        model_id = MULTIMODAL_MODEL_ID if has_media else TEXT_MODEL_ID
        
        # Adjust max tokens based on model and content type
        max_tokens = DEFAULT_MAX_TOKENS
        if has_media:
            max_tokens = max(DEFAULT_MAX_TOKENS, 800)  # More tokens for detailed media analysis
        
        # Log which model is being used (for debugging/monitoring)
        print(f"Using model: {model_id} | Has media: {has_media} | Media type: {media_type} | Max tokens: {max_tokens}")
        
        # Format request body for Claude model using Messages API format
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": DEFAULT_TEMPERATURE,
            "messages": [
                {
                    "role": "user",
                    "content": message_content
                }
            ]
        })

        # Call Bedrock model with appropriate model ID
        response = bedrock_client.invoke_model(
            modelId=model_id,
            body=body,
            accept="application/json",
            contentType="application/json"
        )

        # Response comes as a streaming payload
        response_body = json.loads(response["body"].read())
        
        # Extract model output from Messages API response
        if "content" in response_body and len(response_body["content"]) > 0:
            return response_body["content"][0]["text"]
        else:
            return "No response from model."

    except Exception as e:
        return f"Error during LLM analysis: {str(e)}"
