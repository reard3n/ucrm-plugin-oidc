# Use prepare-build-context.py and the generated immutable build contract.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG BASE_IMAGE
ARG SOURCE_REVISION
ARG NATIVE_PROFILE
ARG CANARY_EMAIL_DOMAIN=""
ARG INCLUDE_LOGIN_BUTTON="0"
LABEL org.opencontainers.image.source="https://github.com/reard3n/ucrm-plugin-oidc" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.base.name="${BASE_IMAGE}" \
      org.opencontainers.image.title="UCRM OIDC native session adapter"
USER root
COPY deployment/bootstrap.cjs /opt/ucrm-oidc-adapter/bootstrap.cjs
COPY deployment/entrypoint.sh /opt/ucrm-oidc-adapter/entrypoint.sh
COPY adapter/*.cjs /opt/ucrm-oidc-adapter/
# No downloads, DB access, credentials, sockets or native service startup.
RUN test -n "$SOURCE_REVISION" \
 && node /opt/ucrm-oidc-adapter/bootstrap.cjs --prepare-image "$NATIVE_PROFILE" "$BASE_IMAGE" "$CANARY_EMAIL_DOMAIN" "$INCLUDE_LOGIN_BUTTON" \
 && chmod 0555 /opt/ucrm-oidc-adapter/entrypoint.sh \
 && chmod 0444 /opt/ucrm-oidc-adapter/*.cjs \
 && mkdir -p /run/ucrm-oidc-adapter
WORKDIR /home/app/unms
ENV UCRM_OIDC_ADAPTER_ENABLED=0
ENTRYPOINT ["/bin/sh", "/opt/ucrm-oidc-adapter/entrypoint.sh"]
# Latest profile must explicitly use command ["api.sh"] as in native Compose.
CMD ["index.js"]
