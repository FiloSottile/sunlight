FROM golang:1.22.0-alpine3.19 as build

WORKDIR /src

RUN apk add build-base

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=1 go install -trimpath ./cmd/sunlight

FROM alpine:3.19 as download

ADD https://github.com/benbjohnson/litestream/releases/download/v0.3.13/litestream-v0.3.13-linux-amd64.tar.gz /tmp/litestream.tar.gz
RUN tar -C /usr/local/bin -xzf /tmp/litestream.tar.gz

FROM alpine:3.19.1

RUN apk add bash curl sqlite

COPY rome/run.sh /usr/local/bin/sunlight.sh
COPY rome/litestream.yml /etc/litestream.yml

WORKDIR /etc/sunlight
COPY rome/roots.pem ./
COPY rome/sunlight.yaml ./

COPY --from=build /go/bin/sunlight /usr/local/bin/sunlight
COPY --from=download /usr/local/bin/litestream /usr/local/bin/litestream

VOLUME /var/db/sunlight

CMD ["bash", "/usr/local/bin/sunlight.sh"]
