.PHONY: install demo test run docker-build docker-demo docker-up clean

install:
	pip install -r requirements.txt

demo:
	python3 demo/run_demo.py

test:
	python3 -m pytest tests/ -v

run:
	uvicorn webui.app:app --host 0.0.0.0 --port 8000 --reload

docker-build:
	docker compose build

docker-demo:
	docker compose run --rm demo

docker-up:
	docker compose up

clean:
	rm -f reports/findings.db
	rm -rf reports/run_logs
	find . -name "__pycache__" -type d -exec rm -rf {} +
