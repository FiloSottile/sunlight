ARG GO_VERSION

FROM golang:${GO_VERSION}-bookworm as build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY *.go ./

WORKDIR /app/cmd/sunlight
RUN go build -o /bin/sunlight .

FROM debian:bookworm

RUN apt-get -y update &&  \
     apt-get install --no-install-recommends  \
     -y curl ca-certificates && \
     rm -rf /var/lib/apt/lists/*

COPY --from=build /bin/sunlight /bin/sunlight

CMD /bin/sunlight
