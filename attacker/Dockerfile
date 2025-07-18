FROM python:3.8-alpine3.12
RUN apk add bash tcpdump bind-tools && pip install scapy==2.4.4

WORKDIR /app
COPY exploit.py /app/

CMD ["sleep", "100000"]