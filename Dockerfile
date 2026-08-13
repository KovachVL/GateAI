ARG GO_VERSION=1.26
ARG SEMGREP_VERSION=1.146.0
ARG OSV_SCANNER_VERSION=v2.2.4
ARG SYFT_VERSION=v1.34.0

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateai ./cmd/gateai

FROM golang:${GO_VERSION}-bookworm AS scanners
ARG OSV_SCANNER_VERSION
ARG SYFT_VERSION
ENV CGO_ENABLED=0 GOBIN=/out
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION} \
 && go install github.com/anchore/syft/cmd/syft@${SYFT_VERSION}

FROM python:3.12-slim-bookworm
ARG SEMGREP_VERSION

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

COPY --from=scanners /out/osv-scanner /usr/local/bin/osv-scanner
COPY --from=scanners /out/syft        /usr/local/bin/syft
COPY --from=build    /out/gateai      /usr/local/bin/gateai

RUN useradd --create-home --uid 10001 gateai
USER gateai
WORKDIR /workspace

ENV SEMGREP_SEND_METRICS=off

RUN mkdir -p /tmp/warmup \
 && semgrep --config p/default --config p/secrets --quiet /tmp/warmup >/dev/null 2>&1 \
 && rmdir /tmp/warmup

ENTRYPOINT ["gateai"]
CMD ["--help"]
