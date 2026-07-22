from celery import Celery

from ai_osop.core.config import settings

celery_app = Celery("ai_osop", broker=settings.redis_uri, backend=settings.redis_uri)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task
def execute_task_celery(task_dict: dict):
    # This will be the entry point for the Celery worker
    print(f"Executing task {task_dict.get('id')} in Celery")
    return {"status": "completed"}
