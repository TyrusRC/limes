# syntax=docker/dockerfile:1.7
# Three stages: Go tools and Python wheels are built with compilers, and the runtime image gets
# only their outputs plus runtime libraries. Cache mounts keep apt, pip and Go downloads between
# builds. Layers run from rarely to often changing, so a code edit rebuilds only the last step.

FROM ubuntu:22.04 AS base
ENV DEBIAN_FRONTEND="noninteractive"
# Also keep downloaded .debs in the apt cache mount instead of deleting them after each install.
RUN ARCH=$(dpkg --print-architecture) \
    && case "${ARCH}" in amd64|arm64) ;; \
      *) echo "Limes not supported, encountered unknown architecture: ${ARCH}" && exit 1 ;; \
    esac \
    && rm -f /etc/apt/apt.conf.d/docker-clean \
    && echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache


# ---- Go tools: built on the runtime's Ubuntu so cgo binaries (naabu/libpcap) match its glibc
FROM base AS gotools
ARG GOVERSION=1.27.1
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git gcc libc6-dev libpcap-dev
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz | tar -xzC /usr/local
ENV GOPATH=/go GO111MODULE=on PATH="/usr/local/go/bin:/go/bin:${PATH}"
# Default-pipeline tools only, pinned. amass is built with CGO disabled.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    printf "\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0\n\
    github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1\n\
    github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0\n\
    github.com/projectdiscovery/katana/cmd/katana@v1.8.0\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1\n\
    github.com/lc/gau/v2/cmd/gau@v2.2.4\n" | \
    xargs -L1 go install -ldflags="-s -w" && \
    CGO_ENABLED=0 go install -ldflags="-s -w" github.com/owasp-amass/amass/v5/cmd/amass@v5.1.1
# assay is our own tool: always the latest main. Adding main's ref busts the layer cache when main
# moves; GOPROXY=direct resolves @main from GitHub so the module proxy cannot serve a stale commit.
ADD https://api.github.com/repos/TyrusRC/assay/git/refs/heads/main /tmp/assay-main.json
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOPROXY=direct go install -ldflags="-s -w" github.com/TyrusRC/assay/cmd/assay@main


# ---- Python wheels: compilers and headers stay in this stage
FROM base AS pywheels
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    python3.10 python3-dev python3-pip build-essential libpq-dev
COPY requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --upgrade pip setuptools==72.1.0 wheel \
    && pip3 wheel -r /tmp/requirements.txt -w /wheels


# ---- Runtime
FROM base AS runtime
ARG OPENGREP_VERSION=1.30.1
LABEL \
    name="Limes" \
    author="TyrusRC" \
    description="Limes: self-hosted external attack surface management."
ENV DATABASE="postgres" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOPATH=/go \
    PATH="${PATH}:/go/bin"

# Runtime libraries only: libpq for psycopg2, pango for weasyprint, libpcap for naabu.
# git is needed to clone vulscan and to install mantis from its repo below.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    python3.10 python3-pip ca-certificates curl wget git netcat nmap geoip-bin geoip-database \
    libpq5 libpango-1.0-0 libpangoft2-1.0-0 libpcap0.8 python3-netaddr

WORKDIR /usr/src/app

COPY --from=gotools /go/bin/ /go/bin/

# opengrep (needed by mantis)
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then OG=opengrep_manylinux_aarch64; else OG=opengrep_manylinux_x86; fi \
    && curl -fsSL -o /usr/local/bin/opengrep https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${OG} \
    && chmod +x /usr/local/bin/opengrep \
    && opengrep --version

COPY requirements.txt /tmp/requirements.txt
RUN --mount=type=bind,from=pywheels,source=/wheels,target=/wheels \
    --mount=type=cache,target=/root/.cache/pip \
    pip3 install --upgrade pip setuptools==72.1.0 \
    && pip3 install --no-index --find-links=/wheels -r /tmp/requirements.txt

RUN nuclei -update-templates

RUN sed -i 's/purge()/truncate()/g' /usr/local/lib/python3.10/dist-packages/whatportis/cli.py \
    && (yes | whatportis --update)

RUN mkdir -p /usr/src/wordlist /usr/src/github /usr/src/scan_results /root/nuclei-templates \
    && wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt

RUN git clone --depth 1 https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan \
    && ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan

# mantis-sast is not on PyPI: always the latest main of the public repo (needs opengrep on PATH, installed above).
# Adding main's ref busts Docker's layer cache whenever main moves, so a rebuild picks up the new commit.
# Kept last before the source copy so a mantis update rebuilds only this layer and the copy.
ADD https://api.github.com/repos/TyrusRC/mantis/git/refs/heads/main /tmp/mantis-main.json
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install 'mantis-sast @ git+https://github.com/TyrusRC/mantis.git@main'

# Copy source code
COPY . /usr/src/app/
