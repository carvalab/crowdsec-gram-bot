# Dev parity only; production path is systemd + install.sh.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev COMMIT=none DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /bot .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /bot /usr/local/bin/crowdsec-gram-bot
USER nobody
ENTRYPOINT ["crowdsec-gram-bot", "bot"]
