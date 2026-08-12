.PHONY: run test tidy docker-up docker-down docker-logs docker-build

run:
	go run ./cmd/server -config configs/config.yaml

test:
	go test ./...

tidy:
	go mod tidy

# 一键启动：MySQL + Redis + App
docker-up:
	docker compose up -d --build

docker-build:
	docker compose build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f app
