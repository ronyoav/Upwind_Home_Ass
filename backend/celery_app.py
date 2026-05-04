import os
from dotenv import load_dotenv
load_dotenv()

from celery import Celery

redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")

celery_app = Celery(
    "email_scorer",
    broker=redis_url,
    backend=redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=300,
    task_track_started=True,
)
