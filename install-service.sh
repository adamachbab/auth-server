#!/bin/sh
set -eu

SERVICE_NAME="${AUTH_SERVICE_NAME:-auth-server}"
SERVICE_PORT="${AUTH_PORT:-1053}"
NATIVE_PORT="${AUTH_NATIVE_PORT:-2230}"
ENV_FILE="/etc/${SERVICE_NAME}.env"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DATA_DIR="${AUTH_DATA_DIR:-/var/lib/${SERVICE_NAME}}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -f "$SCRIPT_DIR/server.js" ] || [ ! -f "$SCRIPT_DIR/package.json" ]; then
  echo "Error: install-service.sh must remain inside the project folder." >&2
  exit 1
fi

case "$SCRIPT_DIR" in
  *' '*)
    echo "Error: move the project to a path without spaces before installing." >&2
    exit 1
    ;;
esac

NODE_BIN=${AUTH_NODE_BIN:-$(command -v node 2>/dev/null || true)}
NPM_BIN=${AUTH_NPM_BIN:-$(command -v npm 2>/dev/null || true)}

if [ -z "$NODE_BIN" ] || [ ! -x "$NODE_BIN" ]; then
  echo "Error: Node.js was not found." >&2
  exit 1
fi
if [ -z "$NPM_BIN" ] || [ ! -x "$NPM_BIN" ]; then
  echo "Error: npm was not found." >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  exec sudo env \
    AUTH_NODE_BIN="$NODE_BIN" \
    AUTH_NPM_BIN="$NPM_BIN" \
    AUTH_SERVICE_NAME="$SERVICE_NAME" \
    AUTH_PORT="$SERVICE_PORT" \
    AUTH_NATIVE_PORT="$NATIVE_PORT" \
    AUTH_DATA_DIR="$DATA_DIR" \
    sh "$SCRIPT_DIR/install-service.sh"
fi

for tool in systemctl openssl useradd; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: $tool is required." >&2
    exit 1
  fi
done

SERVICE_USER="$SERVICE_NAME"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
SERVICE_GROUP=$(id -gn "$SERVICE_USER")

ADMIN_SECRET=''
PREVIOUS_DATABASE_FILE=''
if [ -f "$ENV_FILE" ]; then
  ADMIN_SECRET=$(sed -n 's/^AUTH_ADMIN_SECRET=//p' "$ENV_FILE" | head -n 1)
  PREVIOUS_DATABASE_FILE=$(sed -n 's/^DATABASE_PATH=//p' "$ENV_FILE" | head -n 1)
fi

DATABASE_FILE="$DATA_DIR/database.json"
LEGACY_DATABASE="$SCRIPT_DIR/database.json"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 700 "$DATA_DIR"
MIGRATION_SOURCE=''
case "$PREVIOUS_DATABASE_FILE" in
  /*) [ -f "$PREVIOUS_DATABASE_FILE" ] && MIGRATION_SOURCE="$PREVIOUS_DATABASE_FILE" ;;
esac
if [ -z "$MIGRATION_SOURCE" ] && [ -f "$LEGACY_DATABASE" ]; then
  MIGRATION_SOURCE="$LEGACY_DATABASE"
fi
if [ ! -f "$DATABASE_FILE" ] && [ -n "$MIGRATION_SOURCE" ] && [ "$MIGRATION_SOURCE" != "$DATABASE_FILE" ]; then
  install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 600 "$MIGRATION_SOURCE" "$DATABASE_FILE"
  echo "Migrated the existing database to $DATABASE_FILE"
fi

if [ "${#ADMIN_SECRET}" -lt 32 ]; then
  ADMIN_SECRET=$(openssl rand -hex 32)
fi

TEMP_ENV=$(mktemp)
TEMP_UNIT=$(mktemp)
cleanup() {
  rm -f "$TEMP_ENV" "$TEMP_UNIT"
}
trap cleanup EXIT HUP INT TERM

umask 077
{
  printf 'NODE_ENV=production\n'
  printf 'PORT=%s\n' "$SERVICE_PORT"
  printf 'AUTH_NATIVE_PORT=%s\n' "$NATIVE_PORT"
  printf 'DATABASE_PATH=%s\n' "$DATABASE_FILE"
  printf 'AUTH_ADMIN_SECRET=%s\n' "$ADMIN_SECRET"
} > "$TEMP_ENV"
install -o root -g root -m 600 "$TEMP_ENV" "$ENV_FILE"

echo "Installing production Node dependencies..."
"$NPM_BIN" --prefix "$SCRIPT_DIR" ci --omit=dev
chown -R root:root "$SCRIPT_DIR"
chmod -R go-w "$SCRIPT_DIR"

echo "Initializing or migrating the persistent database..."
runuser -u "$SERVICE_USER" -- env DATABASE_PATH="$DATABASE_FILE" "$NODE_BIN" "$SCRIPT_DIR/scripts/migrate.js"
chown "$SERVICE_USER:$SERVICE_GROUP" "$DATABASE_FILE"
chmod 600 "$DATABASE_FILE"

cat > "$TEMP_UNIT" <<EOF
[Unit]
Description=License authentication service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN $SCRIPT_DIR/server.js
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$DATA_DIR
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

install -o root -g root -m 644 "$TEMP_UNIT" "$UNIT_FILE"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME.service"

if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
  echo "Service failed to start. Recent logs:" >&2
  journalctl -u "$SERVICE_NAME.service" -n 50 --no-pager >&2 || true
  exit 1
fi

echo
echo "$SERVICE_NAME is running HTTP on port $SERVICE_PORT and native TCP on port $NATIVE_PORT as user $SERVICE_USER."
echo "Persistent database: $DATABASE_FILE"
echo "Secrets are stored in $ENV_FILE (root-readable only)."
