// Reference upstream MCP server for proxy tests (stdio). Tools: echo, fail, slow (with progress).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

export function buildServer() {
  const server = new McpServer({ name: "ref-upstream", version: "1.0.0" });
  server.registerTool(
    "echo",
    { description: "echo", inputSchema: { message: z.string() } },
    async ({ message }) => ({
      content: [{ type: "text", text: `Echo: ${message}` }],
    }),
  );
  server.registerTool("fail", { description: "always errors", inputSchema: {} }, async () => ({
    content: [{ type: "text", text: "boom" }],
    isError: true,
  }));
  server.registerTool(
    "slow",
    { description: "progress then result", inputSchema: { steps: z.number() } },
    async ({ steps }, extra) => {
      const token = extra._meta?.progressToken;
      for (let i = 1; i <= steps; i++) {
        if (token !== undefined) {
          await extra.sendNotification({
            method: "notifications/progress",
            params: { progressToken: token, progress: i, total: steps },
          });
        }
        await new Promise((r) => setTimeout(r, 5));
      }
      return { content: [{ type: "text", text: `done ${steps}` }] };
    },
  );
  server.registerTool(
    "ask_roots",
    { description: "server→client request", inputSchema: {} },
    async () => {
      const roots = await server.server.listRoots();
      return { content: [{ type: "text", text: JSON.stringify(roots) }] };
    },
  );
  return server;
}

if (process.argv[2] === "--stdio") {
  await buildServer().connect(new StdioServerTransport());
}
