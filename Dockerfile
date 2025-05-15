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
    postgresql-contrib \

    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure pkg-config
RUN pkg-config --list-all | grep libxml2 || echo "libxml2 not found"


# Install PostgreSQL dependencies
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources && apt-get update
RUN apt-get build-dep -y postgresql-common

# Set working directory
WORKDIR /postgres

# Copy PostgreSQL source code
COPY . .

# Fix permissions
RUN chmod +x configure



# Configure and build PostgreSQL with libxml2
RUN ./configure --without-readline --with-libxml

RUN make -j8

# Start PostgreSQL service
RUN service postgresql start

# Set default command
CMD ["/bin/bash"]


