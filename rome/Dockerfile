FROM golang:1.22.0-alpine3.19 as build

WORKDIR /src

RUN apk add build-base

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=1 go install -trimpath ./cmd/sunlight

FROM alpine:3.19.1

WORKDIR /etc/sunlight
COPY rome/roots.pem ./
COPY rome/sunlight.yaml ./

COPY --from=build /go/bin/sunlight /usr/local/bin/sunlight

VOLUME /var/db/sunlight

CMD ["sh", "-c", "exec /usr/local/bin/sunlight > /var/db/sunlight/sunlight.log"]
