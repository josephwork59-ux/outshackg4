FROM python:3.11-slim

# Non-root user (the Vulnerability Scanner agent lints exactly this pattern
# in scanned Dockerfiles — practice what we preach).
RUN useradd -m -u 1000 appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "webui.app:app", "--host", "0.0.0.0", "--port", "8000"]
