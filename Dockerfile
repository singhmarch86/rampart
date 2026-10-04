# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Set by the release workflow so `rampart -version` reports the real tag and
# commit; a plain `docker build` leaves them as "dev" / "unknown".
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w \
      -X github.com/singhmarch86/rampart/internal/version.Version=${VERSION} \
      -X github.com/singhmarch86/rampart/internal/version.Commit=${COMMIT}" \
    -o /out/rampart ./cmd/rampart

# /app (binary + default config) is owned by root and read-only at runtime —
# deliberate for a distroless image. Anything the process needs to WRITE
# (the event log) goes in /data instead, which is chowned to the nonroot
# UID below. Writing straight into /app would fail with "permission
# denied": COPY sets root ownership regardless of the base image's USER,
# and distroless has no shell to chmod it after the fact — this was caught
# by actually running the built image with logging enabled, not by
# inspection.
RUN mkdir -p /data && \
    sed 's#events_path: "rampart-events.jsonl"#events_path: "/data/rampart-events.jsonl"#' \
        configs/rampart.example.yaml > /out/rampart.yaml

# Distroless static, non-root: no shell, no package manager, minimal attack
# surface for a security tool that will itself be internet-facing.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /out/rampart /app/rampart
COPY --from=builder /out/rampart.yaml /app/configs/rampart.yaml
COPY configs/waf-custom-rules /app/configs/waf-custom-rules
COPY configs/schemas /app/configs/schemas
COPY --from=builder --chown=65532:65532 /data /data

# 8080: proxy (public). 9090: dashboard (see docs/DEPLOYMENT.md — do not
# expose this publicly without authentication in front of it). /data:
# mount a volume here to persist the event log across container restarts.
EXPOSE 8080 9090
VOLUME ["/data"]

ENTRYPOINT ["/app/rampart"]
CMD ["-config", "/app/configs/rampart.yaml"]
