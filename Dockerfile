FROM alpine:latest
EXPOSE 57687
ADD go-tiny-mfa /opt
CMD ["/opt/go-tiny-mfa"]
