FROM golang:1.26-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pqtls ./cmd/web

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/pqtls /pqtls

ENV PORT=8080
EXPOSE 8080

CMD ["/pqtls"]
