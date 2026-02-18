FROM gcr.io/distroless/static:nonroot@sha256:01e550fdb7ab79ee7be5ff440a563a58f1fd000ad9e0c532e65c3d23f917f1c5
COPY ./envoy-extension-server-linux-amd64 /usr/local/bin/envoy-extension-server

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/envoy-extension-server"]
