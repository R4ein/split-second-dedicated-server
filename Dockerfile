# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.27-alpine AS build
WORKDIR /src

# The server module has no third-party dependencies.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/ssserver ./cmd/ssserver \
 && mkdir -p /out/data

# ---- runtime ----
# Static binary on distroless: no shell, no package manager, non-root user.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ssserver /ssserver
COPY --from=build --chown=65532:65532 /out/data /data

ENV SS_DATA=/data \
    SS_BIND=0.0.0.0
VOLUME ["/data"]
EXPOSE 31120/udp 31121/udp

USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/ssserver", "healthcheck"]

ENTRYPOINT ["/ssserver"]
