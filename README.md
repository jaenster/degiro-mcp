# degiro-mcp

An MCP server for your DeGiro account, written in Zig. Read your portfolio, orders, transactions and
prices, and optionally place orders, from Claude or any other MCP client. Tool results are
[TOON](https://github.com/jaenster/toon) to keep them small.

Unofficial: it uses DeGiro's private web API, which can change or break at any time. Hobby project,
use at your own risk.

To have your agent set it up, paste this:

```
Fetch and follow the instructions to set me up with degiro-mcp from https://raw.githubusercontent.com/jaenster/degiro-mcp/main/SETUP.md
```

## Local (stdio)

Grab a binary from the [releases](https://github.com/jaenster/degiro-mcp/releases) or build one with
Zig 0.16 (`zig build -Doptimize=ReleaseSafe`). Then, for Claude Code:

```sh
claude mcp add degiro \
  -e DEGIRO_USERNAME=... -e DEGIRO_PASSWORD=... -e DEGIRO_TOTP_SECRET=... \
  -- /path/to/degiro-mcp stdio
```

or in Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "degiro": {
      "command": "/path/to/degiro-mcp",
      "args": ["stdio"],
      "env": { "DEGIRO_USERNAME": "...", "DEGIRO_PASSWORD": "...", "DEGIRO_TOTP_SECRET": "..." }
    }
  }
}
```

`DEGIRO_TOTP_SECRET` is the seed of your DeGiro two-factor setup (base32, or the whole `otpauth://`
URI from the QR code), not a six-digit code. Add `DEGIRO_TRADING=true` to enable the order tools.

### Without secrets in the config

Pasting your password and TOTP seed into an MCP config leaves them in plaintext on disk. On macOS,
[hush](https://github.com/jaenster/hush) keeps them encrypted and injects them only into the
process:

```sh
hush set degiro DEGIRO_USERNAME you
hush set degiro DEGIRO_PASSWORD '...'
hush set degiro DEGIRO_TOTP_SECRET '...'   # or 'op://Private/DeGiro/...' to read from 1Password

claude mcp add degiro -- hush --env=degiro -- /path/to/degiro-mcp stdio
```

For Claude Desktop, use `"command": "/opt/homebrew/bin/hush"` with
`"args": ["--env=degiro", "--", "/path/to/degiro-mcp", "stdio"]` and no `env`. Desktop apps don't
see your shell's `PATH`, so the full path is needed.

## Tools

| Tool | What it does |
|-|-|
| `get_portfolio` | Positions with P/L in EUR, cash per currency, account totals |
| `get_open_orders` | Orders still open |
| `get_order_history` | Order events in a date range (max 90 days) |
| `get_transactions` | Executed trades with fees |
| `get_cash_movements` | Account statement (deposits, dividends, fees, FX) |
| `search_products` | Find product ids by name, ticker or ISIN |
| `get_products` | Details and allowed order types for product ids |
| `get_price_history` | Live quote plus OHLC candles |
| `check_order` | Validates an order and returns its costs and a `confirmation_id`; places nothing |
| `check_conversion` | Same for a currency exchange to or from EUR; `all` converts a whole foreign balance |
| `confirm_order` | Places a checked order; a `confirmation_id` is good for one order within 10 minutes |
| `cancel_order` | Cancels an open order |

The last four only exist with `DEGIRO_TRADING=true`.

## Remote (Streamable HTTP)

`degiro-mcp serve` runs it as a remote MCP server, e.g. as a claude.ai custom connector. It is its
own OAuth 2.1 authorization server (dynamic client registration, PKCE, refresh tokens) and leaves the
actual login to an OIDC provider of your choice. Tokens are sealed with `OAUTH_KEY`, so nothing is
stored.

| Env | Meaning |
|-|-|
| `PUBLIC_BASE_URL` | Public origin, e.g. `https://degiro.example.com` |
| `PORT` | Listen port (default 8080) |
| `OAUTH_KEY` | 64 hex characters (`openssl rand -hex 32`); turns on the authorization server |
| `MCP_OIDC_ISSUER` | Issuer of the OIDC provider |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | This server's client at that provider; its redirect URI is `<PUBLIC_BASE_URL>/oauth/callback` |
| `MCP_ALLOWED_EMAILS` | Comma-separated emails allowed in |
| `MCP_TOKEN` | Optional static bearer token instead of OAuth |

## Development

```sh
zig build test
scripts/dev.sh call get_portfolio    # one tool, credentials from 1Password (DEGIRO_OP_ITEM)
```
