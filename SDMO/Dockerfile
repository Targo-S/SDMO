FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY sdmo ./sdmo
RUN useradd --create-home appuser
USER appuser

CMD ["python", "-m", "sdmo.gateway"]
