# Reference image for the docker-compose topology.
FROM python:3.12-slim

WORKDIR /app

# Core has no dependencies; install dev/optional extras if you want tests or the
# real scanners inside the image.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app CYBERGUARD_LLM=deterministic

# Non-root by default (practice what the Policy Checker preaches).
RUN useradd --create-home --uid 10001 cyber && chown -R cyber /app
USER cyber

CMD ["python", "-m", "cli", "scan", "--config", "demo/scenario.json"]
