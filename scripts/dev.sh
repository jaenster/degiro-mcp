#!/bin/sh
# Runs degiro-mcp locally with the DeGiro credentials pulled from 1Password, e.g.
#   scripts/dev.sh call get_portfolio
#   MCP_TOKEN=dev scripts/dev.sh serve
set -eu
ITEM="${DEGIRO_OP_ITEM:-op://Private/DEGIRO}"
DEGIRO_USERNAME="$(op read "$ITEM/username")"
DEGIRO_PASSWORD="$(op read "$ITEM/password")"
DEGIRO_TOTP_SECRET="$(op read "$ITEM/one-time password")"
export DEGIRO_USERNAME DEGIRO_PASSWORD DEGIRO_TOTP_SECRET
cd "$(dirname "$0")/.."
zig build
exec ./zig-out/bin/degiro-mcp "$@"
