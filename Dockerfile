FROM alpine:latest
LABEL maintainer="tinymfa@parzival.link"
LABEL description="tinymfa is a time based one time pad (TOTP) solution written in golang. It implements RFC 6238."
EXPOSE 57687

ARG ARCH=amd64
ARG USER_ID=57687
ARG GROUP_ID=57687

USER root
RUN mkdir -p /opt/go-tiny-mfa/bin && \
    mkdir -p /opt/go-tiny-mfa/secrets && \
    addgroup --gid ${GROUP_ID} tinymfa && \
    adduser \
        --no-create-home --disabled-password \
        --ingroup tinymfa --shell /bin/sh \
        --home /opt/go-tiny-mfa --uid ${USER_ID} tinymfa && \
    chown -R ${USER_ID}:${GROUP_ID} /opt/go-tiny-mfa
VOLUME [ "/opt/go-tiny-mfa/secrets" ]
COPY --chown=${USER_ID}:${GROUP_ID} build/go-tiny-mfa-${ARCH} /opt/go-tiny-mfa/bin/tiny-mfa

USER tinymfa
HEALTHCHECK --interval=5s --timeout=5s --start-period=30s CMD ["/opt/go-tiny-mfa/bin/tiny-mfa", "--healthcheck"]
CMD ["/opt/go-tiny-mfa/bin/tiny-mfa"]