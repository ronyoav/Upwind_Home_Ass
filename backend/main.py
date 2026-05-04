import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.models.email_request import EmailAnalysisRequest
from backend.worker import run_analysis

app = FastAPI(title="Malicious Email Scorer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/analyze")
def submit_analysis(request: EmailAnalysisRequest):
    task = run_analysis.delay(request.model_dump())
    return {"task_id": task.id}


@app.get("/api/v1/result/{task_id}")
def get_result(task_id: str):
    task = run_analysis.AsyncResult(task_id)
    if task.state in ("PENDING", "STARTED"):
        return {"status": "pending"}
    elif task.state == "SUCCESS":
        return {"status": "ready", "result": task.result}
    else:
        return {"status": "error", "detail": str(task.info)}
