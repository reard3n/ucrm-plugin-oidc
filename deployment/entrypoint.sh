#!/bin/sh
# Preserve native PID1/exec, privilege drop, migration and worker ownership.
# Other vendor commands (including device-ws.sh) never install the API hook.
case "${1:-}" in
  index.js|api.sh)
    if ! node /opt/ucrm-oidc-adapter/bootstrap.cjs --activate; then
      export UCRM_OIDC_ADAPTER_ENABLED=0
    fi
    ;;
esac
exec docker-entrypoint.sh "$@"
