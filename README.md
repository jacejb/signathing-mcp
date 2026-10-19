# Signathing MCP server

Send PDFs for legally binding e-signature from any AI agent, and get back a certified copy whose history anyone can verify without trusting the sender or Signathing.

- **Remote server:** `https://signathing.com/api/mcp` (Streamable HTTP). Sign in with OAuth, or send an API key as a bearer header.
- **Free tier:** 100 documents a month, no card. Then $0.06 a document (101 to 500), $0.03 (501 to 3,000), $0.025 (3,001+), prepaid.
- **Evidence:** every signing event is appended to a public hash chain, sealed daily and archived with the Internet Archive. [signathing.com/transparency](https://signathing.com/transparency)
- **Docs:** [signathing.com/developers](https://signathing.com/developers) · OpenAPI: [/api/v1/openapi.json](https://signathing.com/api/v1/openapi.json) · [/llms.txt](https://signathing.com/llms.txt)

Operated by AllContraX LLC, Kentucky, USA. The Signathing app and website stay free for people; the API and MCP server are for software.

## Tools

| Tool | What it does |
| --- | --- |
| `send_document` | Upload a PDF (https URL or base64), name up to 25 signers and 25 view-only recipients, optionally place signature, initials, date, name, email, text, number, checkbox, radio or dropdown fields. Signers get a private link by email (and text). One billable unit. |
| `get_document` | Status, signers with viewed/signed times, download links, event history. |
| `list_documents` | Your recent documents, filterable by status. |
| `remind_document` | Re-send links to everyone who has not signed (once an hour). |
| `void_document` | Withdraw an open document. Within 10 minutes of sending, the unit is refunded. |
| `get_account` | Prepaid balance, documents used this month, free documents left, projected run-out. |
| `get_evidence` | Court-ready evidence package: PDF hashes, every signer and event with its position in the public evidence log, and the recipe to verify it. |
| `verify_signature_code` | Look up the code stamped beside any Signathing signature. Works for any document. |

## Connect

### Claude.ai, ChatGPT, Grok apps (OAuth)

Add a custom connector / remote MCP server with the URL `https://signathing.com/api/mcp`. You will be sent to signathing.com to sign in and approve. Disconnect any time under API in your Signathing dashboard.

### Claude Code

```bash
claude mcp add --transport http signathing https://signathing.com/api/mcp \
  --header "Authorization: Bearer sk_live_..."
```

Or without a key, using OAuth: `claude mcp add --transport http signathing https://signathing.com/api/mcp` and run `/mcp` to sign in.

### Cursor, VS Code, Windsurf (`mcp.json`)

```json
{ "mcpServers": { "signathing": {
    "url": "https://signathing.com/api/mcp",
    "headers": { "Authorization": "Bearer sk_live_..." } } } }
```

### Grok (xAI Responses API)

```json
{ "type": "mcp", "server_label": "signathing",
  "server_url": "https://signathing.com/api/mcp",
  "headers": { "Authorization": "Bearer sk_live_..." } }
```

### Claude API (Messages API, `mcp_servers`)

```json
{ "type": "url", "name": "signathing", "url": "https://signathing.com/api/mcp",
  "authorization_token": "sk_live_..." }
```

### stdio-only clients

This repository ships a dependency-free bridge for clients that cannot speak HTTP MCP:

```json
{ "mcpServers": { "signathing": {
    "command": "npx", "args": ["-y", "github:jacejb/signathing-mcp"],
    "env": { "SIGNATHING_API_KEY": "sk_live_..." } } } }
```

Create a key at [signathing.com/dashboard/api](https://signathing.com/dashboard/api).

## Why a third party instead of letting the agent sign things itself

A signature only matters on the day it is disputed. On that day the party that controlled the signing system is the party with something to gain, and its own logs are "trust me." Signathing is nobody's party to the contract, and it does not ask you to trust it either: every signing event goes into one public hash chain, each entry commits to the private details through a hash without publishing them, each day is sealed and archived by the Internet Archive, and the verifier in `verifier/` recomputes all of it from a document's evidence package.

```bash
node verifier/verify-signathing.mjs evidence.json original.pdf signed.pdf
```

## Example: an agent sends a lease

```
User: Send the lease at https://files.example.com/lease.pdf to Pat Lee (pat@example.com) for signature.
Agent -> send_document { file_url, title: "Lease", signers: [{ name: "Pat Lee", email: "pat@example.com" }] }
Signathing -> { id: 58, status: "sent", signers: [{ signing_url: "https://signathing.com/sign/..." }], billing: { charged_tenths: 0 } }
```

Pat gets an email, signs in the browser, and the agent can call `get_document` or receive a webhook. The certified PDF is digitally sealed and carries a certificate page and a verification code per signature.

## License

MIT for this repository. The Signathing service has its own [terms](https://signathing.com/terms) and [privacy policy](https://signathing.com/privacy).
