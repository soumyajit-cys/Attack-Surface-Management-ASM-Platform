from celery import Celery

celery=Celery(
"worker",
broker="redis://redis"
)