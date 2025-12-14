import requests
from urllib.parse import urlparse
from llm_utils import get_llm_judgement
from typing import Dict, Any

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

async def analyze(url: str) -> Dict[str, Any]:
    """
    Analyze a URL for spam, fake news, phishing, or malicious content
    """
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Parse URL to extract domain info
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not domain:
            return {
                "type": "url",
                "url": url,
                "error": "Invalid URL format - no domain found",
                "judgement": "Invalid URL provided for analysis"
            }
        
        # Set headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Fetch the URL content with timeout
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, stream=True)
        response.raise_for_status()
        
        # Check content length to avoid downloading huge files
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) > 50 * 1024 * 1024:  # 50MB limit
            return {
                "type": "url",
                "url": url,
                "error": f"Content too large: {content_length} bytes (50MB limit)",
                "judgement": "Cannot analyze - content exceeds size limit"
            }
        
        content_type = response.headers.get('content-type', '').lower()
        
        # Read the actual content
        response_content = response.content
        
        # Handle different content types
        if 'text/html' in content_type:
            return await _analyze_html_content(url, domain, response_content.decode('utf-8', errors='ignore'), response)
        elif 'image/' in content_type:
            return await _analyze_image_from_url(url, domain, response_content, content_type)
        elif 'application/pdf' in content_type:
            return await _analyze_pdf_from_url(url, domain, response_content)
        else:
            return await _analyze_generic_content(url, domain, response_content.decode('utf-8', errors='ignore'), content_type)
            
    except requests.exceptions.RequestException as e:
        return {
            "type": "url",
            "url": url,
            "error": f"Failed to fetch URL: {str(e)}",
            "judgement": f"Cannot analyze URL due to access error: {str(e)}"
        }
    except Exception as e:
        return {
            "type": "url",
            "url": url,
            "error": f"Analysis error: {str(e)}",
            "judgement": f"Error during URL analysis: {str(e)}"
        }

async def _analyze_html_content(url: str, domain: str, html_content: str, response) -> Dict[str, Any]:
    """Analyze HTML webpage content"""
    if not BS4_AVAILABLE:
        return {
            "type": "url",
            "url": url,
            "domain": domain,
            "error": "BeautifulSoup not available for HTML analysis",
            "judgement": f"HTML content from {domain} detected but cannot parse without BeautifulSoup library"
        }
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract key information
        title = soup.find('title')
        title_text = title.get_text().strip() if title else "No title"
        
        # Extract meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc.get('content', '') if meta_desc else ''
        
        # Extract main text content
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()
        
        # Get text content
        text_content = soup.get_text()
        # Clean up whitespace
        lines = (line.strip() for line in text_content.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        clean_text = ' '.join(chunk for chunk in chunks if chunk)
        
        # Limit text length for analysis
        if len(clean_text) > 3000:
            clean_text = clean_text[:3000] + "..."
        
        # Extract suspicious patterns
        suspicious_indicators = _check_suspicious_patterns(url, domain, soup, clean_text)
        
        # Prepare content for LLM analysis
        analysis_content = f"""
URL: {url}
Domain: {domain}
Title: {title_text}
Description: {description}

Content to analyze:
{clean_text}

Suspicious indicators found: {suspicious_indicators}
"""
        
        # Get LLM judgment
        judgement = get_llm_judgement(content=analysis_content)
        
        return {
            "type": "url",
            "url": url,
            "domain": domain,
            "title": title_text,
            "description": description,
            "content_length": len(clean_text),
            "suspicious_indicators": suspicious_indicators,
            "status_code": response.status_code,
            "judgement": judgement
        }
        
    except Exception as e:
        return {
            "type": "url",
            "url": url,
            "error": f"HTML parsing error: {str(e)}",
            "judgement": f"Error parsing webpage content: {str(e)}"
        }

async def _analyze_image_from_url(url: str, domain: str, image_data: bytes, content_type: str) -> Dict[str, Any]:
    """Analyze image content from URL"""
    try:
        # Use the multimodal LLM capability for image analysis
        judgement = get_llm_judgement(
            content=f"This image was found at URL: {url} (domain: {domain}). Analyze if this image or the source appears to be spam, fake, or malicious.",
            media_data=image_data,
            media_type=content_type
        )
        
        return {
            "type": "url",
            "content_type": "image",
            "url": url,
            "domain": domain,
            "image_size_bytes": len(image_data),
            "judgement": judgement
        }
    except Exception as e:
        return {
            "type": "url",
            "url": url,
            "error": f"Image analysis error: {str(e)}",
            "judgement": f"Error analyzing image from URL: {str(e)}"
        }

async def _analyze_pdf_from_url(url: str, domain: str, pdf_data: bytes) -> Dict[str, Any]:
    """Analyze PDF content from URL"""
    if not PYMUPDF_AVAILABLE:
        return {
            "type": "url",
            "content_type": "pdf",
            "url": url,
            "domain": domain,
            "pdf_size_bytes": len(pdf_data),
            "error": "PyMuPDF not available for PDF analysis",
            "judgement": f"PDF from {domain} detected but cannot extract text without PyMuPDF library"
        }
    
    try:
        doc = fitz.open(stream=pdf_data, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        
        if not text.strip():
            analysis_content = f"PDF from URL: {url} (domain: {domain}) appears to be empty or contains no extractable text."
        else:
            analysis_content = f"""
PDF from URL: {url}
Domain: {domain}
Extracted text content:
{text[:2000]}{"..." if len(text) > 2000 else ""}
"""
        
        judgement = get_llm_judgement(content=analysis_content)
        
        return {
            "type": "url",
            "content_type": "pdf",
            "url": url,
            "domain": domain,
            "pdf_size_bytes": len(pdf_data),
            "extracted_text_length": len(text),
            "judgement": judgement
        }
    except Exception as e:
        return {
            "type": "url",
            "url": url,
            "domain": domain,
            "error": f"PDF analysis error: {str(e)}",
            "judgement": f"Error analyzing PDF from URL: {str(e)}"
        }

async def _analyze_generic_content(url: str, domain: str, content: str, content_type: str) -> Dict[str, Any]:
    """Analyze generic content from URL"""
    analysis_content = f"""
URL: {url}
Domain: {domain}
Content Type: {content_type}
Content: {content[:2000]}{"..." if len(content) > 2000 else ""}
"""
    
    judgement = get_llm_judgement(content=analysis_content)
    
    return {
        "type": "url",
        "content_type": content_type,
        "url": url,
        "domain": domain,
        "content_length": len(content),
        "judgement": judgement
    }

def _check_suspicious_patterns(url: str, domain: str, soup: BeautifulSoup, text: str) -> list:
    """Check for common spam/phishing indicators"""
    indicators = []
    
    # Check for suspicious domains
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        indicators.append("Suspicious top-level domain")
    
    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link']
    if any(shortener in domain for shortener in shorteners):
        indicators.append("URL shortener detected")
    
    # Check for excessive redirects or suspicious URL patterns
    if len(url) > 100:
        indicators.append("Unusually long URL")
    
    if url.count('-') > 5 or url.count('.') > 5:
        indicators.append("Suspicious URL structure")
    
    # Check content for spam indicators
    spam_keywords = [
        'click here now', 'limited time offer', 'act now', 'free money',
        'you have won', 'congratulations', 'urgent', 'verify your account',
        'suspended account', 'click to verify', 'tax refund', 'inheritance'
    ]
    
    text_lower = text.lower()
    for keyword in spam_keywords:
        if keyword in text_lower:
            indicators.append(f"Spam keyword detected: '{keyword}'")
    
    # Check for excessive capitalization
    if soup:
        caps_text = ''.join([t for t in soup.get_text() if t.isupper()])
        total_text = ''.join([t for t in soup.get_text() if t.isalpha()])
        if total_text and len(caps_text) / len(total_text) > 0.3:
            indicators.append("Excessive capitalization detected")
    
    # Check for suspicious forms
    if soup:
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'password'}):
                indicators.append("Password input form detected")
    
    return indicators
