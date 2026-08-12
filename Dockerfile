# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS builder
WORKDIR /src

ENV GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/server ./cmd/server

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates curl netcat-openbsd tzdata \
  && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
  && echo Asia/Shanghai > /etc/timezone

COPY --from=builder /out/server /app/server
COPY configs/config.docker.yaml /app/configs/config.yaml
COPY scripts/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/server", "-config", "/app/configs/config.yaml"]
