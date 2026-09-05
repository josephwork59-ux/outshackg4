# Deliberately misconfigured demo Dockerfile — used only as a scan target.
FROM python:latest

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

ADD https://example.com/bootstrap.sh /app/bootstrap.sh

ENV API_KEY=hardcoded-super-secret-token

COPY . .

# No USER directive — container runs as root.
CMD ["python", "app.py"]
