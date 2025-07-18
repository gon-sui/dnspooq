FROM alpine:3.13

# Copy pre-compiled dnsmasq from existing image
COPY --from=gonkori/dnspooq-dnsmasq:v8 /usr/local/sbin/dnsmasq /usr/local/sbin/dnsmasq

# Create startup script for dynamic cache IP configuration
RUN mkdir -p /etc/dnsmasq && \
    echo "log-queries" > /etc/dnsmasq/dnsmasq.conf && \
    echo "no-resolv" >> /etc/dnsmasq/dnsmasq.conf && \
    echo "# Cache IP will be set by environment variable" >> /etc/dnsmasq/dnsmasq.conf

EXPOSE 53 53/udp

# Use environment variable for cache IP configuration
# 変更: デフォルトキャッシュIPを10.10.0.14から192.168.115.151に更新
# 理由: 新しいネットワーク構成要件に合わせるため
CMD sh -c "echo server=\${CACHE_IP:-192.168.115.151} >> /etc/dnsmasq/dnsmasq.conf && echo Starting dnsmasq with cache IP: \${CACHE_IP:-192.168.115.151} && cat /etc/dnsmasq/dnsmasq.conf && /usr/local/sbin/dnsmasq -k --log-facility=- --conf-file=/etc/dnsmasq/dnsmasq.conf"