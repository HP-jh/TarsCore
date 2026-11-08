FROM golang:1.22-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o tarscore ./cmd/tars-core

FROM alpine:3.19

RUN apk --no-cache add ca-certificates curl
RUN mkdir -p /etc/tarscore /models /var/lib/tarscore /usr/local/bin

COPY --from=builder /build/tarscore /usr/local/bin/tarscore

# Install llama-server if available
RUN if [ -f /models/llama-server ]; then \
      chmod +x /models/llama-server; \
    fi

VOLUME ["/etc/tarscore", "/models", "/var/lib/tarscore"]

EXPOSE 18889

ENTRYPOINT ["/usr/local/bin/tarscore"]
CMD ["--port", "18889"]
