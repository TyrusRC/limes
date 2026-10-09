# Base image
FROM ubuntu:22.04

ARG GOVERSION=1.27.1
ARG OPENGREP_VERSION=1.30.1
ARG ASSAY_COMMIT=a79e350

RUN ARCH=$(dpkg --print-architecture) \
    && case "${ARCH}" in amd64|arm64) ;; \
      *) echo "Limes not supported, encountered unknown architecture: ${ARCH}" && exit 1 ;; \
    esac

LABEL \
    name="Limes" \
    author="TyrusRC" \
    description="Limes: self-hosted external attack surface management."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Install Python
RUN apt update -y && \
    apt install -y \
    python3.10 \
    python3-dev \
    python3-pip 

# Install essential packages
RUN apt install -y --no-install-recommends \
    build-essential \
    cmake \
    geoip-bin \
    geoip-database \
    gcc \
    git \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpcap-dev \
    netcat \
    nmap \
    wget \
    curl \
    python3-netaddr

RUN ARCH=$(dpkg --print-architecture) \ 
    && curl -L https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local

# Install Rust for orjson
RUN set -e; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip3 install maturin

# Make directory for app
WORKDIR /usr/src/app

ENV GO111MODULE=on
# Default-pipeline tools only, pinned. amass is built with CGO disabled.
RUN printf "\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0\n\
    github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1\n\
    github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0\n\
    github.com/projectdiscovery/katana/cmd/katana@v1.8.0\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1\n\
    github.com/lc/gau/v2/cmd/gau@v2.2.4\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    CGO_ENABLED=0 go install -ldflags="-s -w" -v github.com/owasp-amass/amass/v5/cmd/amass@v5.1.1 && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build

# assay (no release tags exist upstream; pinned by commit)
RUN go install -ldflags="-s -w" -v github.com/TyrusRC/assay/cmd/assay@${ASSAY_COMMIT} && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build

# opengrep (needed by mantis)
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then OG=opengrep_manylinux_aarch64; else OG=opengrep_manylinux_x86; fi \
    && curl -fsSL -o /usr/local/bin/opengrep https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${OG} \
    && chmod +x /usr/local/bin/opengrep \
    && opengrep --version

# Update Nuclei and Nuclei-Templates
RUN nuclei -update-templates

# Copy requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade setuptools==72.1.0
RUN pip3 install -r /tmp/requirements.txt --no-cache-dir
# mantis-sast is not on PyPI; pinned by commit of the public repo (needs opengrep on PATH, installed above)
# NOTE: Ubuntu's pip 22.0 mis-builds PEP 621 projects as UNKNOWN-0.0.0, so a newer pip is used for this one install.
RUN pip3 install --no-cache-dir --upgrade pip && python3 -m pip install --no-cache-dir 'https://github.com/TyrusRC/mantis/archive/ceeabca2f3e3c1a2df1cba05d925ce15aeaa57a3.tar.gz'

RUN sed -i 's/purge()/truncate()/g' /usr/local/lib/python3.10/dist-packages/whatportis/cli.py \
    && (yes | whatportis --update)

RUN mkdir -p /usr/src/wordlist /usr/src/github /usr/src/scan_results /root/nuclei-templates \
    && wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt

RUN git clone --depth 1 https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan \
    && ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan

# Copy source code
COPY . /usr/src/app/
