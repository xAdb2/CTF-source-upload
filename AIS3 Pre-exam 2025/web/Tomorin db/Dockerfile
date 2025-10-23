FROM golang:1.23.1-alpine

RUN mkdir -p /app
WORKDIR /app

COPY ./src /app/

RUN go build -o server .

EXPOSE 30000

CMD ["/app/server"]
