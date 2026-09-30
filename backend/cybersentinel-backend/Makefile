.PHONY: all help train-dga train-ddos train-beacon train-tls train-exfil train-all clean

PROJECT_ROOT := $(shell dirname $(shell realpath $(lastword $(MAKEFILE_LIST))))

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*##"}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

all: ## Install dependencies and verify setup
	@echo "CyberSentinel Backend setup complete"
	@echo "Run 'make train-all' to train all models"
	@echo "Run 'make generate-traffic' to generate test PCAP data"

train-dga: ## Train DGA classifier
	python scripts/train_dga.py

train-ddos: ## Train DDoS anomaly detector
	python scripts/train_ddos.py

train-beacon: ## Train C2 Beacon detector
	python scripts/train_beacon.py

train-tls: ## Train TLS malware classifier
	python scripts/train_tls.py

train-exfil: ## Train Exfiltration detector
	python scripts/train_exfil.py

train-all: ## Train all ML models
	@echo "Training DGA classifier..."
	python scripts/train_dga.py
	@echo "Training DDoS detector..."
	python scripts/train_ddos.py
	@echo "Training Beacon detector..."
	python scripts/train_beacon.py
	@echo "Training TLS malware classifier..."
	python scripts/train_tls.py
	@echo "Training Exfiltration detector..."
	python scripts/train_exfil.py
	@echo "All models trained successfully!"

clean: ## Remove model artifacts and generated data
	rm -f app/models/artifacts/*.joblib
	rm -f app/models/artifacts/*.pkl
	rm -f app/models/artifacts/*.json
	rm -f data/models/*.txt
	rm -f data/alerts.db
	@echo "Artifacts cleaned"

docker-up: ## Start Docker services
	docker-compose up -d

docker-down: ## Stop Docker services
	docker-compose down

generate-traffic: ## Generate test PCAP data via scripts
	@bash scripts/generate_traffic.sh --help 2>/dev/null || echo "See scripts/generate_traffic.sh for usage"

benchmark: ## Run benchmark pipeline
	python scripts/benchmark.py