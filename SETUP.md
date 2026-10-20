# Agent setup: degiro-mcp

You are setting up the degiro-mcp stdio server (https://github.com/jaenster/degiro-mcp) for the user.
It is an unofficial MCP server for their DeGiro brokerage account. Follow these steps in order.

**Never ask the user for their DeGiro password or TOTP seed, and never put them in a command you
run.** Anything you see ends up in the conversation log. Wherever a secret is needed, give the user a
command to run in their own terminal, outside this session.

## 1. Install the binary

Pick the release asset for this machine from https://github.com/jaenster/degiro-mcp/releases/latest:

| OS / CPU | Asset |
|-|-|
| macOS Apple Silicon | `degiro-mcp-aarch64-macos.tar.gz` |
| macOS Intel | `degiro-mcp-x86_64-macos.tar.gz` |
| Linux x86_64 | `degiro-mcp-x86_64-linux-musl.tar.gz` |
| Linux arm64 | `degiro-mcp-aarch64-linux-musl.tar.gz` |
| Windows x86_64 | `degiro-mcp-x86_64-windows.zip` |

Download it and `SHA256SUMS` from
`https://github.com/jaenster/degiro-mcp/releases/latest/download/<file>`, and check the archive's
hash against `SHA256SUMS`; stop if it does not match. Extract the binary to `~/.local/bin/degiro-mcp`
(Windows: `%LOCALAPPDATA%\Programs\degiro-mcp\degiro-mcp.exe`). On macOS, run
`xattr -d com.apple.quarantine <binary>` if the attribute is set, because the build is not notarized.

Check that it runs: `degiro-mcp stdio` with no credentials set must print
`DEGIRO_USERNAME, DEGIRO_PASSWORD and DEGIRO_TOTP_SECRET must be set`.

## 2. Ask the user

- Should Claude be able to place orders? If yes, set `DEGIRO_TRADING=true` (not a secret). Every order
  still needs a check and then an explicit confirmation.
- Which client: Claude Code, Claude Desktop, or both?

## 3. Credentials

They need three values: their DeGiro username, their password, and the TOTP seed of their DeGiro
two-factor setup. The seed is the base32 text or `otpauth://` URI behind the QR code, not a six-digit
code. If they only have the QR code in an authenticator app, they may need to set up two-factor again
in DeGiro to see the seed.

**macOS with [hush](https://github.com/jaenster/hush) (preferred).** The secrets stay encrypted and
never appear in a config file. If `hush` is missing, offer `brew install jaenster/tap/hush &&
brew services start jaenster/tap/hush`. Then have the user run this in their own terminal (`read -rs`
keeps the values out of shell history):

```sh
for k in DEGIRO_USERNAME DEGIRO_PASSWORD DEGIRO_TOTP_SECRET; do
  printf '%s: ' "$k"; read -rs v; echo; hush set degiro "$k" "$v"; done; unset v
```

Instead of the real value, a 1Password user can enter a reference like `op://Private/DeGiro/password`.
Check with `hush ls degiro`, which shows keys only.

**Without hush.** The values go into the client's config file in plaintext. Say so, and leave filling
them in to the user.

## 4. Register the server

Claude Code with hush:

```sh
claude mcp add degiro -- hush --env=degiro -- ~/.local/bin/degiro-mcp stdio
```

Add `-e DEGIRO_TRADING=true` before `--` if they want trading. Without hush, give the user
`claude mcp add degiro -e DEGIRO_USERNAME=... -e DEGIRO_PASSWORD=... -e DEGIRO_TOTP_SECRET=... --
<binary> stdio` to run themselves.

Claude Desktop: add to `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`). Use absolute paths, because
desktop apps don't see the shell's `PATH`:

```json
{
  "mcpServers": {
    "degiro": {
      "command": "/opt/homebrew/bin/hush",
      "args": ["--env=degiro", "--", "/Users/<you>/.local/bin/degiro-mcp", "stdio"]
    }
  }
}
```

Without hush, `command` is the binary, `args` is `["stdio"]`, and an `env` object holds the three
values. The user fills those in themselves. Restart Claude Desktop afterwards.

## 5. Verify

Have the user start a new session and ask for their open orders. A login error means the username,
password or seed is wrong; the server's stderr has DeGiro's reason. Don't print portfolio contents as
part of setup.
