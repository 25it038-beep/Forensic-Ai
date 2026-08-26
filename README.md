# 🛡️ AI & Forensic Email SOC Platform

> **An enterprise-grade, real-time Phishing, BEC & Digital Forensics Intelligence Platform.**  
> Powered by **FastAPI**, **React 19 + TypeScript**, **Scikit-learn**, **NLTK**, and **Threat Intelligence (WHOIS, DNS, GeoIP, VirusTotal, OCR & QR Quishing Detection)**.

---

## 📋 Table of Contents
1. [Architecture Overview](#-architecture-overview)
2. [Prerequisites](#-prerequisites)
3. [Quick Start (Run from Project Root)](#-option-1-run-from-project-root-recommended)
4. [Run from Specific Directories](#-option-2-run-from-specific-subdirectories)
   - [Backend Directory (`/backend`)](#running-from-backend-directory)
   - [Frontend Directory (`/frontend`)](#running-from-frontend-directory)
5. [Docker & Docker Compose (Single-Command Setup)](#-option-3-docker--docker-compose)
6. [Machine Learning Model Training](#-machine-learning-model-training)
7. [Environment Configuration (`.env`)](#-environment-configuration)
8. [API Documentation & Endpoints](#-api-documentation)
9. [Troubleshooting & Common Directory Errors](#-troubleshooting--directory-issues)

---

## 🏗️ Architecture Overview

```
efinal-main/
│
├── backend/                  # FastAPI REST Backend & AI Pipeline
│   ├── app/
│   │   ├── main.py           # FastAPI entrypoint & API endpoints
│   │   ├── classifier.py     # ML phishing classification logic
│   │   ├── indicators.py     # Threat intel & IOC extraction
│   │   ├── utils.py          # Email RFC header parsing, WHOIS, DNS, OCR
│   │   ├── models.py         # SQLAlchemy DB models
│   │   └── database.py       # SQLite / PostgreSQL connection
│   ├── dataset/              # Phishing email training data
│   ├── models/               # Saved model.pkl & vectorizer.pkl
│   ├── training/             # train.py script for ML retraining
│   ├── requirements.txt      # Python dependencies
│   └── .env.example          # Environment variable template
│
├── frontend/                 # React 19 + Vite + TypeScript SOC Dashboard
│   ├── src/                  # React components, SOC attack map, charts
│   ├── package.json          # Node dependencies
│   ├── vite.config.ts        # Vite configuration & backend proxy
│   └── tailwind.config.js    # Cyberpunk / SOC dark theme styles
│
├── Dockerfile                # Multi-stage production container
├── docker-compose.yml        # Multi-container orchestration
└── README.md                 # Documentation
```

---

## ⚙️ Prerequisites

- **Python**: `3.10` or higher (`python --version`)
- **Node.js**: `18.x` or higher & **npm** (`node -v`, `npm -v`)
- **Git** (optional)
- **Docker & Docker Compose** (optional, for containerized run)

---

## 🚀 Option 1: Run from Project Root (Recommended)

Run both the Backend and Frontend concurrently from the main project root folder (`efinal-main/`):

### 1. Set Up the Backend
```bash
# Windows (PowerShell / Command Prompt)
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
cd ..

# Linux / macOS (Bash / Zsh)
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..
```

### 2. Set Up the Frontend
```bash
cd frontend
npm install
cd ..
```

### 3. Start Backend & Frontend in Parallel

#### Terminal 1 — Backend (Port 8000):
```bash
# Windows (PowerShell)
.\backend\venv\Scripts\python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000

# Linux / macOS
./backend/venv/bin/python3 -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

#### Terminal 2 — Frontend (Port 5173):
```bash
# From project root
npm --prefix frontend run dev
```

Open your browser at: **`http://localhost:5173`**  
Backend Swagger API: **`http://127.0.0.1:8000/docs`**

---

## 📁 Option 2: Run from Specific Subdirectories

If your terminal is already inside `backend/` or `frontend/`, use the following commands:

### Running from `backend/` Directory

```bash
# 1. Navigate to backend directory
cd backend

# 2. Create and activate virtual environment
# Windows:
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Optional: Copy environment configuration
# Windows: copy .env.example .env | Linux/macOS: cp .env.example .env

# 5. Launch FastAPI backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
> 🌐 Backend will be live at: **`http://127.0.0.1:8000`** (Swagger docs at `/docs`)

---

### Running from `frontend/` Directory

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install NPM dependencies
npm install

# 3. Start Vite Development Server
npm run dev
```
> 🌐 Frontend SOC Dashboard will be live at: **`http://localhost:5173`**  
*(Vite automatically proxies `/api` and `/health` requests to `http://127.0.0.1:8000`)*

---

## 🐳 Option 3: Docker & Docker Compose

To build and run the entire unified stack (Frontend + Backend + ML Models + SQLite) with a single command from the project root:

```bash
# Build and run container
docker compose up --build

# Run in background (detached mode)
docker compose up -d

# Stop containers
docker compose down
```

Access the unified application at: **`http://localhost:10000`**

---

## 🧠 Machine Learning Model Training

The application comes with pre-trained models. If you modify `phishing_email.csv` or want to retrain the TF-IDF and Classifier models:

### Run from Root Directory:
```bash
# Windows
.\backend\venv\Scripts\python backend/training/train.py

# Linux / macOS
./backend/venv/bin/python3 backend/training/train.py
```

### Run from `backend/` Directory:
```bash
cd backend
python training/train.py
```
> This will generate fresh `model.pkl` and `vectorizer.pkl` files inside `backend/models/`.

---

## 🔐 Environment Configuration

Create a `.env` file inside `backend/` (or copy from `backend/.env.example`):

```ini
# Server Settings
PORT=8000
DATABASE_URL=sqlite:///./phishing_detector.db
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Optional Threat Intelligence API Keys (Heuristic fallbacks are used if omitted)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
NVIDIA_API_KEY=your_nvidia_api_key_here
NVIDIA_MODEL=meta/llama-3.2-11b-vision-instruct

# Optional Cache Configuration (Defaults to in-memory)
REDIS_URL=redis://localhost:6379/0

# Upload Limits
MAX_FILE_SIZE=10485760
```

---

## 🔌 API Documentation

Once the backend is running, access interactive OpenAPI documentation at:
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc UI**: `http://127.0.0.1:8000/redoc`

### Key Endpoints:
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/predict` | Predict phishing risk & extract NLP features from raw email text |
| `POST` | `/api/forensics/analyze-email` | Full RFC 5322 header parsing, SPF/DKIM/DMARC & Received-hop trace |
| `POST` | `/api/forensics/upload-eml` | Upload raw `.eml` or `.msg` file for automated forensic inspection |
| `POST` | `/api/analyze-url` | WHOIS, DNS, SSL certificate & reputation analysis for suspicious URLs |
| `GET` | `/api/stats` | Global threat statistics, scan volume, and telemetry |
| `GET` | `/health` | Service healthcheck endpoint |

---

## 🛠️ Troubleshooting & Directory Issues

### 1. `ModuleNotFoundError: No module named 'app'`
- **Cause**: Running `uvicorn app.main:app` from the project root instead of inside `backend/`.
- **Fix**:
  - Either `cd backend` first, then run `uvicorn app.main:app --reload --port 8000`.
  - Or from root run: `python -m uvicorn backend.app.main:app --reload --port 8000`.

### 2. Frontend shows `Network Error` or `Failed to fetch`
- **Cause**: Backend is not running or running on an unexpected port.
- **Fix**: Make sure FastAPI is running on port `8000` (`http://127.0.0.1:8000`). If using a custom port, set `VITE_API_PROXY_TARGET=http://127.0.0.1:YOUR_PORT` in `frontend/.env`.

### 3. Missing OCR / QR Detection Dependencies (Optional)
- For advanced QR-code scanning and OCR attachment forensics:
  - **Ubuntu/Debian**: `sudo apt-get install -y libzbar0 tesseract-ocr`
  - **macOS**: `brew install zbar tesseract`
  - **Windows**: Install Tesseract OCR from UB-Mannheim and ensure it is in your system `PATH`.

---

## 👥 Authors & Team
- **Harshan Seliyan B.S.** — Cybersecurity & AI Lead
