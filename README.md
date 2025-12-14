# 🛡️ FactScope  
**Real-time Misinformation, Spam & Phishing Detection with Explainable AI**

FactScope is an AI-powered browser-based solution that helps users identify **fake news, AI-generated content, spam links, phishing messages, and misleading media** in real time.  
Instead of just labeling content as *fake* or *safe*, FactScope explains **why** something looks suspicious in **plain English**, helping users make informed decisions online.

---

## 🚀 Problem Statement

As AI-generated content becomes more sophisticated, misinformation, phishing, and spam are spreading faster than ever across news websites, emails, and messaging platforms.  
Existing tools are often reactive, require manual uploads, or provide binary verdicts without explanation—making them impractical for everyday users.

**FactScope addresses this gap by acting as an always-on, explainable trust layer directly where users consume content.**

---

## 💡 Solution Overview

FactScope works as a **browser extension** with a **Python backend** that analyzes content from the current tab with a single click.

### What it can analyze:
- 📰 News articles  
- 💬 Messages & text content  
- 🔗 Links & URLs  
- 🖼️ Images  
- 📄 PDFs  
- 🎥 Videos (via metadata & transcription pipeline)

### How it works:
1. User clicks **“Scan current tab”** in the extension.
2. Content is extracted and sent to the backend.
3. **Elasticsearch** checks the content against known spam/misinformation patterns.
4. **AWS Bedrock LLMs** analyze semantics and generate a plain-English explanation.
5. The user receives:
   - A **Trust Score**
   - A **clear explanation of why the content is suspicious or safe**

---

## ✨ Key Features

- ✅ One-click scanning (no uploads required)
- ✅ Real-time analysis on websites users already visit
- ✅ Explainable AI (no technical jargon)
- ✅ Covers spam, phishing, misinformation, and AI-generated content
- ✅ Scalable architecture using Elasticsearch + AWS AI services

---

## 🧠 Why This Is Unique

Unlike many “AI vs AI” detection tools, FactScope:
- Works **inline** instead of forcing users into dashboards
- Focuses on **everyday threats** (spam links, phishing emails, fake forwards)
- Explains *why* content is flagged, not just *what*
- Uses **Elasticsearch as a knowledge base**, not just for logging
- Is designed for the **Hack-to-the-Future** theme—solving a growing 2030-era trust problem today

---

## 🏗️ Architecture Overview

Browser Extension
|
v
FastAPI Backend (Python)
|
+--> Elasticsearch (pattern matching, similarity search)
|
+--> AWS Bedrock (LLM explanations)
|
+--> AWS Textract / Rekognition / Transcribe (media processing)


---

## 🧰 Tech Stack

### Frontend
- Chrome Extension (Manifest V3)
- JavaScript, HTML, CSS

### Backend
- Python
- FastAPI
- REST APIs

### AI & Search
- **AWS Bedrock** (LLM-based analysis & explanations)
- **Elasticsearch** (spam/misinformation indexing & similarity search)

### Cloud & Utilities
- AWS SDK (boto3)
- Elastic Cloud / Local Elasticsearch

---

## 📂 Repository Structure (Example)


├── frontend/ # Browser extension code
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── popup.css
│   ├── background.js
│   ├── content/
│   │   ├── content.js
│   │   └── inject.js
│   └── assets/
│       ├── icon.png
│       └── logo.svg
├── backend/ # FastAPI backend
│ ├── analyzers/ # Text, image, pdf, video analyzers
│ ├── elastic_utils.py
│ ├── llm_utils.py
│ ├── main.py
│ └── config.py
├── README.md


---

## 🧪 How to Run (High Level)

1. Start Elasticsearch (local or cloud).
2. Configure AWS credentials in `config.py`.
3. Run backend:
   ```bash
   uvicorn main:app --reload


Load the browser extension via chrome://extensions.

Open any news site and click Scan current tab.

🎯 Hackathon Context

This project was built as part of Hack-the-Impossible / Hack-to-the-Future, with over 7,000+ participants.
FactScope focuses on future-ready digital trust, addressing misinformation challenges that will only intensify in the coming decade.

🌱 Future Improvements

Native mobile integration (SMS & messaging apps)

Multilingual misinformation detection

Enterprise phishing protection

Kibana dashboards for trend monitoring

Stronger media deepfake detection

🙌 Acknowledgements

Built during a hackathon using Elasticsearch and AWS AI services, with a focus on real-world impact, explainability, and usability.