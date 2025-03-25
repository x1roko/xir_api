FROM golang:1.24.1-alpine

WORKDIR /app

COPY . .

RUN go mod tidy
RUN go mod vendor

RUN go build -o main .

CMD ["./main"]
