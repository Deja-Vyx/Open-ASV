# OpenASV — web UI, worker and scan engines (Nmap, testssl.sh, Nuclei). OWASP ZAP runs as a separate service.
FROM python:3.12-slim-bookworm

ARG TARGETARCH
ARG TESTSSL_REF=v3.2.5
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_REF=v10.5.1

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap libcap2-bin git ca-certificates curl unzip bsdextrautils dnsutils procps openssl tzdata \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+eip /usr/bin/nmap

RUN git clone --depth 1 --branch "${TESTSSL_REF}" https://github.com/testssl/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

RUN set -eux; arch="${TARGETARCH:-amd64}"; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; rm /tmp/nuclei.zip; nuclei -version

RUN git clone --depth 1 --branch "${NUCLEI_TEMPLATES_REF}" https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates \
    && rm -rf /opt/nuclei-templates/.git && test -d /opt/nuclei-templates/http

RUN useradd -m -u 10001 openasv && mkdir -p /data && chown -R openasv /data /opt/nuclei-templates
USER openasv

WORKDIR /app
COPY --chown=openasv pyproject.toml README.md LICENSE ./
COPY --chown=openasv openasv ./openasv
RUN pip install --user ".[pdf]" "ssh-audit==3.9.0" "wafw00f==2.4.2"
COPY --chown=openasv config ./config

ENV PATH=/home/openasv/.local/bin:$PATH \
    OPENASV_CONFIG_DIR=/app/config OPENASV_DATA_DIR=/data OPENASV_NUCLEI_TEMPLATES=/opt/nuclei-templates \
    OPENASV_PRIVILEGED=1 NMAP_PRIVILEGED=1

VOLUME ["/data"]
EXPOSE 9100
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:9100/healthz || exit 1
CMD ["openasv", "serve", "--host", "0.0.0.0", "--port", "9100"]
