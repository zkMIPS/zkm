FROM rustlang/rust:nightly AS builder
RUN \
  useradd --create-home -u 50000 -G 100 jenkins

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    libtool \
    curl \
    make \
    gcc \
    g++ \
    unzip \
    pkg-config \
    openssl \
    libssl-dev \
    wget \
    vim \
    git \
    cmake \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# install golang
ENV GOLANG_VERSION=1.22.5
ENV GOLANG_DOWNLOAD_URL=https://go.dev/dl/

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        GOARCH=amd64; \
    elif [ "$ARCH" = "aarch64" ]; then \
        GOARCH=arm64; \
    else \
        echo "Unsupported architecture"; exit 1; \
    fi && \
    wget ${GOLANG_DOWNLOAD_URL}go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz && \
    rm go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz


USER jenkins

# install mips target
RUN \
    curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/zkMIPS/toolchain/refs/heads/main/setup.sh | sh

ENV PATH=/usr/local/go/bin:$PATH

CMD ["bash"]

# docker build -t zkm/zkmips:compile .
# docker run -it --rm -v ./:/zkm zkm/zkmips:compile
# compile rust mips
# cd /zkm/prover/examples/sha2-rust && cargo build -r --target=mips-unknown-linux-musl
# cd /zkm/prover/examples/revme && cargo build -r --target=mips-unknown-linux-musl
# compile go mips
# cd /zkm/prover/examples/add-go && GOOS=linux GOARCH=mips GOMIPS=softfloat go build .
# cd /zkm/prover/examples/sha2-go && GOOS=linux GOARCH=mips GOMIPS=softfloat go build .
