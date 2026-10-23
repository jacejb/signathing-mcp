# Glama (and anyone else) can run the stdio bridge in a container.
# The bridge has no dependencies: it forwards MCP JSON-RPC from stdin to
# https://signathing.com/api/mcp with your API key.
#
#   docker build -t signathing-mcp .
#   docker run -i -e SIGNATHING_API_KEY=sk_live_... signathing-mcp
FROM node:20-alpine
WORKDIR /app
COPY package.json README.md LICENSE ./
COPY bin ./bin
COPY verifier ./verifier
ENV NODE_ENV=production
ENTRYPOINT ["node", "bin/signathing-mcp.mjs"]
