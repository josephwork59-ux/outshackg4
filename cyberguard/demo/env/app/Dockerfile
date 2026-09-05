# Demo Dockerfile (intentionally contains misconfigurations).
FROM python:latest

ENV APP_API_KEY=sk_live_9c3f8a1e7b2d4f60a1c5e9d8b7a6f5e4

WORKDIR /srv/app

ADD https://example.com/bootstrap/install.sh /tmp/install.sh
RUN apt-get update && apt-get install -y curl build-essential

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
