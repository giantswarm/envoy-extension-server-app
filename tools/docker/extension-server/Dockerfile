FROM gcr.io/distroless/static:nonroot@sha256:cba10d7abd3e203428e86f5b2d7fd5eb7d8987c387864ae4996cf97191b33764
COPY ./envoy-extension-server-linux-amd64 /usr/local/bin/envoy-extension-server

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/envoy-extension-server"]
