# 服务器版镜像：nfmonitor server（不含桌面窗口）。
#   docker build -t nfmonitor .
# 部署见 README「服务器版」和 docker-compose.yml。
FROM node:22-bookworm-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/frontend/dist ./frontend/dist
ARG VERSION=""
RUN V="${VERSION:-$(sed -n 's/^var version = "\(.*\)"$/\1/p' main.go)}" && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${V}" -o /out/nfmonitor . && \
    mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nfmonitor /nfmonitor
COPY --from=build --chown=65532:65532 --chmod=700 /out/data /data
ENV NFMONITOR_DATA=/data HOME=/data
VOLUME /data
EXPOSE 8787
USER 65532:65532
ENTRYPOINT ["/nfmonitor", "server"]
# 默认放在反向代理后面（代理负责 HTTPS）。直接对外提供 HTTPS 时改用 -tls-cert/-tls-key。
CMD ["-addr", "0.0.0.0:8787", "-behind-proxy", "-trusted-proxies", "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.1/32"]
