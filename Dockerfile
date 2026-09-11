FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download github.com/go-telegram/bot || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bot .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /bot /usr/local/bin/bot
ENTRYPOINT ["bot"]
