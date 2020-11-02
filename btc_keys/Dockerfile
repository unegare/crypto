FROM alpine:latest as builder

WORKDIR /app

RUN apk update && apk add --no-cache clang openssl openssl-dev build-base

COPY . .

RUN make

FROM alpine:latest as runner

RUN apk update && apk add --no-cache libstdc++ openssl openssl-dev

WORKDIR /app

COPY --from=builder /app/a.out .

ENTRYPOINT ["/app/a.out"]
