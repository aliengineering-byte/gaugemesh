# syntax=docker/dockerfile:1.7
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release --bin gaugemesh

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.description="Semantics-preserving routing for agents, MCP servers, and models."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/aliengineering-byte/gaugemesh"
LABEL org.opencontainers.image.title="GaugeMesh"
LABEL io.modelcontextprotocol.server.name="io.github.aliengineering-byte/gaugemesh"
COPY --from=build /src/target/release/gaugemesh /usr/local/bin/gaugemesh
USER nonroot:nonroot
EXPOSE 8090 8092
ENTRYPOINT ["/usr/local/bin/gaugemesh"]
CMD ["demo"]
