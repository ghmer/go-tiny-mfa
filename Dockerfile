FROM alpine:latest
EXPOSE 57687
ARG ARCH=amd64
RUN mkdir -p /opt/go-tiny-mfa/{bin,secrets}
COPY build/go-tiny-mfa-${ARCH} /opt/go-tiny-mfa/bin/tiny-mfa
RUN addgroup --gid 57687 tinymfa && adduser --no-create-home --disabled-password --ingroup tinymfa --shell /bin/bash --home /opt/go-tiny-mfa --uid 57687 tinymfa
RUN chown -R tinymfa:tinymfa /opt/go-tiny-mfa
WORKDIR /opt/go-tiny-mfa
USER tinymfa
HEALTHCHECK --interval=5s --timeout=5s --start-period=30s CMD /opt/go-tiny-mfa/bin/tiny-mfa --healthcheck
CMD ["/opt/go-tiny-mfa/bin/tiny-mfa"]