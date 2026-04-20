FROM alpine:3.19

RUN apk add --no-cache bash netcat-openbsd curl coreutils procps iproute2 python3 \
 && rm -rf /var/cache/apk/*

WORKDIR /app
COPY service.sh /app/service.sh
RUN chmod +x /app/service.sh

EXPOSE 8080
CMD ["/app/service.sh"]
