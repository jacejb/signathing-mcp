# Installing the Signathing MCP server (for an AI agent doing the setup)

Signathing sends PDFs for e-signature. The server is hosted; nothing is built or compiled. Pick ONE of the two setups below.

## What the user must give you first

An API key. The user creates it at https://signathing.com/dashboard/api (a free account, no card; sign-in is a one-time code by email or text). The key starts with `sk_live_`. Ask the user for it. Do not invent one, and do not write it into any file that is committed to a repository.

Setup A needs no key if the client can do OAuth in a browser.

## Setup A: remote server (preferred when the client supports remote MCP)

Add a remote (Streamable HTTP) server in the client's own settings format. The two values are the URL `https://signathing.com/api/mcp` and one header, `Authorization: Bearer <key>`. In most clients that looks like this:

```json
{
  "mcpServers": {
    "signathing": {
      "url": "https://signathing.com/api/mcp",
      "headers": { "Authorization": "Bearer sk_live_REPLACE_WITH_THE_USERS_KEY" }
    }
  }
}
```

If the client supports OAuth for remote servers, leave `headers` out. The user is sent to signathing.com to sign in and approve.

## Setup B: stdio bridge (for clients that only run local commands)

Requires Node.js 18 or newer. No install step: `npx` fetches the bridge from this repository. It has no dependencies.

```json
{
  "mcpServers": {
    "signathing": {
      "command": "npx",
      "args": ["-y", "github:jacejb/signathing-mcp"],
      "env": { "SIGNATHING_API_KEY": "sk_live_REPLACE_WITH_THE_USERS_KEY" }
    }
  }
}
```

On Windows, if `npx` is not found by the client, use `"command": "cmd"` with `"args": ["/c", "npx", "-y", "github:jacejb/signathing-mcp"]`.

## Check that it works

1. List the tools. There are twelve, including `get_account`, `send_document` and `list_documents`. Listing works even without a key.
2. Call `get_account` with no arguments. A working setup answers with the account's balance and the free documents left this month. An answer that says to sign in or send a key means the key is missing or wrong.

## Try a send without reaching anyone

Call `send_document` with `"test": true`:

```json
{
  "file_url": "https://signathing.com/templates/non-disclosure-agreement/pdf",
  "title": "Setup check",
  "signers": [{ "name": "Test Person", "email": "test@example.com" }],
  "test": true
}
```

In test mode every message goes to the account's own email address, nothing is charged, the title is marked [TEST], and the document erases itself after 7 days.

## Things to know before calling the tools

- `send_document` and `send_from_template` email or text real people unless `test` is true. A send past the 100 free documents a month draws down the account's prepaid balance.
- `void_document` and `delete_document` cannot be undone. They are for a document the user has clearly asked to withdraw or erase.
- Each signer's `signing_url` opens the document as that signer for whoever holds it. Treat it as private.
- Full reference: https://signathing.com/developers
