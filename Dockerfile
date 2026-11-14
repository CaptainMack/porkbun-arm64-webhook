# Cross-compiles on the build host's architecture (no QEMU), then ships a static
# binary on distroless as a non-root user. Base images are pinned by digest.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build

WORKDIR /workspace
ENV GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY porkbun/ ./porkbun/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags '-s -w' -o /out/webhook .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/webhook /usr/local/bin/webhook
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/webhook"]
