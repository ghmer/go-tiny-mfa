FROM alpine:latest
EXPOSE 57687

ARG ARCH=amd64
ARG USER_ID=57687
ARG GROUP_ID=57687

USER root
RUN mkdir -p /opt/go-tiny-mfa/bin && mkdir -p /opt/go-tiny-mfa/secrets && touch /opt/go-tiny-mfa/secrets/.placeholder
RUN addgroup --gid ${GROUP_ID} tinymfa && adduser --no-create-home --disabled-password --ingroup tinymfa --shell /bin/bash --home /opt/go-tiny-mfa --uid ${USER_ID} tinymfa
RUN chown -R ${USER_ID}:${GROUP_ID} /opt/go-tiny-mfa
COPY --chown=${USER_ID}:${GROUP_ID} build/go-tiny-mfa-${ARCH} /opt/go-tiny-mfa/bin/tiny-mfa

USER tinymfa
HEALTHCHECK --interval=5s --timeout=5s --start-period=30s CMD /opt/go-tiny-mfa/bin/tiny-mfa --healthcheck
CMD ["/opt/go-tiny-mfa/bin/tiny-mfa"]