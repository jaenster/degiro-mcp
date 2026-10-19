FROM alpine:3.21 AS build
ARG ZIG_VERSION=0.16.0
RUN apk add --no-cache curl xz ca-certificates
RUN ARCH=$(uname -m) \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ARCH}-linux-${ZIG_VERSION}.tar.xz" \
       | tar -xJ -C /opt \
    && ln -s /opt/zig-*/zig /usr/local/bin/zig
WORKDIR /src
COPY build.zig build.zig.zon ./
RUN zig build --fetch
COPY src src
RUN zig build test && zig build -Doptimize=ReleaseSafe -Dtarget=$(uname -m)-linux-musl

# scratch plus the CA bundle: the binary is static, and std.http.Client reads the bundle from
# /etc/ssl/certs to verify DeGiro, vwd and the OIDC provider.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/zig-out/bin/degiro-mcp /degiro-mcp
USER 65534
EXPOSE 8080
ENTRYPOINT ["/degiro-mcp"]
CMD ["serve"]
