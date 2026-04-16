# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o jwtproxy .

# Final minimal image
FROM scratch
COPY --from=builder /app/jwtproxy /jwtproxy
CMD ["/jwtproxy"]