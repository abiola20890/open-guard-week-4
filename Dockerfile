# ---------- BUILD STAGE ----------
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git (needed for some Go dependencies)
RUN apk add --no-cache git

# Copy go mod files first
COPY go.mod go.sum ./

# Download dependencies
RUN GOPROXY=direct go mod download

# Copy entire project
COPY . .

# Build the application
RUN go build -o openguard main.go


# ---------- RUN STAGE ----------
FROM alpine:latest

WORKDIR /app


COPY --from=builder /app/openguard .


COPY .env .env


EXPOSE 8081

# Run the app
CMD ["./openguard"]