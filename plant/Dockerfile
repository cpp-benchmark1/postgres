FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    build-essential \
    netcat-openbsd \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source files
COPY plant-vuln-cwe134-ex1.c /app/
COPY plant-vuln-cwe134-ex2.c /app/

# Compile the programs
RUN gcc -o vuln-cwe134-ex1 plant-vuln-cwe134-ex1.c && \
    gcc -o vuln-cwe134-ex2 plant-vuln-cwe134-ex2.c

# Expose port 8080
EXPOSE 8080

# Keep container running
CMD ["/bin/bash"] 