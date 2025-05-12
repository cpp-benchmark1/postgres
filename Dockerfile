FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install essential build tools and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    libreadline-dev \
    zlib1g-dev \
    flex \
    bison \
    pkg-config \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Install CodeQL CLI
RUN wget https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \
    && tar -xvzf codeql-bundle-linux64.tar.gz \
    && rm codeql-bundle-linux64.tar.gz \
    && mv codeql /opt/codeql

# Add CodeQL to PATH
ENV PATH="/opt/codeql:${PATH}"

# Set working directory
WORKDIR /postgres

# Copy PostgreSQL source code
COPY . .

# Fix permissions
RUN chmod +x configure

# Configure and build PostgreSQL
RUN ./configure --without-readline \
    && make

# Clean up to reduce image size
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Set default command
CMD ["/bin/bash"] 