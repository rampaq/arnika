# Dockerfile for WireGuard container
FROM debian:trixie-slim@sha256:66b37a5078a77098bfc80175fb5eb881a3196809242fd295b25502854e12cbec

# RUN apk add --no-cache wireguard-tools iptables ip6tables
RUN apt-get update
RUN apt-get install -y \
        bc \
        iptables \
        iproute2 \
        iputils-ping \
        procps \
        iperf3 \
        wireguard-tools && \
    rm -rf /var/lib/apt/lists/*

# Create directory for WireGuard config
RUN mkdir -p /etc/wireguard /etc/rosenpass /app/bin /app/keys

# install rosenpass
#RUN wget https://github.com/rosenpass/rosenpass/releases/download/v0.2.2/rosenpass-x86_64-linux-0.2.2.tar -O /tmp/rosenpass.tar && \
#    tar -xf /tmp/rosenpass.tar -C /opt/rosenpass && \
#    rm -f /tmp/rosenpass.tar
# procpc -- wait
#        iptables \
#        ip6tables \
#        iputils \
#        wireguard-tools && \


# Copy the entrypoint script
COPY entrypoint.sh /app
COPY bin /app/bin
COPY fit_connect/ /app/fit_connect
RUN chmod +x /app/entrypoint.sh && \
    chmod -R +x /app/bin
ENV PATH="$PATH:/app/bin"
WORKDIR /app
ENV PQC_PSK_FILE="/app/keys/pqc_psk"

ENTRYPOINT ["/app/entrypoint.sh"]
