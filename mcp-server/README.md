# AgentAudit MCP Server

Security audit capabilities for AI agents via the Model Context Protocol.

## Tools

### `audit_package`
Clone a Git repository and prepare it for security analysis. Returns source code + audit methodology for the calling agent to analyze.

```
Input:  { "source_url": "https://github.com/owner/repo" }
Output: Source code files + 3-pass audit instructions
```

The calling agent's LLM performs the actual analysis using the returned audit prompt, then calls `submit_report` with the results.

### `submit_report`
Upload a completed audit report to the AgentAudit registry.

```
Input:  { "report": { "skill_slug": "...", "source_url": "...", "risk_score": 0-100, ... } }
Output: Confirmation with report ID and registry URL
```

### `check_package`
Look up a package in the AgentAudit security registry.

```
Input:  { "package_name": "fastmcp" }
Output: Latest audit results, risk score, findings
```

## Setup

### Claude Desktop / Claude Code
Add to your MCP config (`~/.claude/mcp.json`):
```json
{
  "mcpServers": {
    "agentaudit": {
      "command": "node",
      "args": ["/path/to/agentaudit/mcp-server/index.mjs"]
    }
  }
}
```

### Cursor
Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "agentaudit": {
      "command": "node",
      "args": ["/path/to/agentaudit/mcp-server/index.mjs"]
    }
  }
}
```

### Environment Variables
- `AGENTAUDIT_API_KEY` — API key for uploading reports (or use `config/credentials.json`)

## How it Works

```
Agent calls audit_package("https://github.com/owner/repo")
         ↓
MCP Server clones repo, reads source files (max 300KB)
         ↓
Returns: audit prompt + source code
         ↓
Agent's LLM analyzes code (3-pass: UNDERSTAND → DETECT → CLASSIFY)
         ↓
Agent calls submit_report(report_json)
         ↓
Report uploaded to agentaudit.dev/skills/{slug}
```

The audit quality depends on the calling agent's model. Works best with Claude Opus/Sonnet, GPT-4, or similar capable models.

## Requirements

- Node.js 18+
- Git (for cloning repos)
- `@modelcontextprotocol/sdk` (installed via npm)
