FROM alpine:latest
RUN apk add --no-cache ca-certificates && \
    adduser -D -g '' appuser
COPY urlhs /urlhs
USER appuser
ENTRYPOINT ["/urlhs"]
