# sec_pull

This directory contains the backend and frontend for the vulnerability scanning demo.

## Backend
- Python FastAPI app for code vulnerability scanning
- Dummy integrations for CodeBERT and Gemini/AI
- Vulnerable Express.js demo app (test.js)

## Frontend
- Simple HTML demo for scanning URLs

## How to Run Backend
```sh
cd sec_pull/backend
pip install -r requirements.txt
python code_review.py
```

## How to Run Demo App
```sh
cd sec_pull/backend
node test.js
```
