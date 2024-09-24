FROM golang:1.23.1 AS build
WORKDIR /app
COPY go.mod go.sum ./
COPY ./vendor ./vendor
COPY ./*.go ./
COPY ./assets ./assets
RUN CGO_ENABLED=0 GOOS=linux go build -o /sifisha

# Run the tests in the container
FROM build AS run-test
RUN go test -v ./...

#FROM debian:bookworm

FROM alpine:latest

WORKDIR /

COPY --from=build /sifisha /sifisha

EXPOSE 2848

#RUN apt update && apt install -y openssh-client

RUN apk update \
        && apk upgrade \
        && apk add --no-cache \
        ca-certificates \
        && update-ca-certificates 2>/dev/null || true

RUN apk add openssh-client

RUN mkdir -p ~/.ssh
RUN "ssh-keyscan" "zh2587s3.rsync.net" >> ~/.ssh/known_hosts

ENV LOG_LEVEL=info
ENTRYPOINT ["/sifisha", "serve"]
