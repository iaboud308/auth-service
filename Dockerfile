


# Use Go image to build the application
FROM golang:1.17-alpine

WORKDIR /app

# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
RUN go build -o auth-service .

# Expose the service on port 8081 (inside the container)
EXPOSE 5002

# Start the application
CMD ["./auth-service"]
