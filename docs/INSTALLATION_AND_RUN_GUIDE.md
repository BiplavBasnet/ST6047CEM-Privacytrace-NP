# Installation and Run Guide

## Backend

```powershell
cd backend
python -m pip install -r requirements.txt
docker compose up -d
pytest app/tests/test_workflow_integrity.py -v --tb=short
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Frontend

```powershell
cd frontend
npm install
npm test
npm run build
npm run dev
```

Open `http://127.0.0.1:5173`.

## Notes

Set `VITE_API_BASE_URL` only if the backend is not running on `http://127.0.0.1:8000`.

Actual AI provider keys belong in local environment files, not committed source.
