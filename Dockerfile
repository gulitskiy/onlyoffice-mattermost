# Используем Ubuntu
FROM ubuntu:22.04

# --------------------
# Node.js 20
# --------------------
RUN apt-get update && \
    apt-get install -y curl ca-certificates gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# --------------------
# Go 1.23
# --------------------
RUN apt-get update && \
    apt-get install -y wget && \
    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz && \
    rm -rf /var/lib/apt/lists/*

# --------------------
# System deps
# --------------------
RUN apt-get update && \
    apt-get install -y \
      git \
      make \
      bash \
      g++ \
      python3 \
      python3-pip \
      jq \
    && rm -rf /var/lib/apt/lists/*

# --------------------
# ENV
# --------------------
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"

# --------------------
# Versions check
# --------------------
RUN node -v && npm -v && go version

# --------------------
# npm config
# --------------------
RUN npm config set legacy-peer-deps true

WORKDIR /onlyoffice-mattermost

# --------------------
# Clone repo
# --------------------
RUN git clone https://github.com/gulitskiy/onlyoffice-mattermost.git .

# --------------------
# Build
# --------------------
CMD ["make", "dist"]
