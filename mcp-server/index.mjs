#!/usr/bin/env node
/**
 * AgentAudit MCP Server
 * 
 * Provides security audit capabilities via Model Context Protocol.
 * 
 * Tools:
 *   - audit_package: Clone a repo, read source files, return with audit prompt
 *   - submit_report: Upload a completed audit report to agentaudit.dev
 *   - check_package: Look up a package in the AgentAudit registry
 * 
 * Usage:
 *   node mcp-server/index.mjs
 * 
 * Configure in Claude/Cursor/etc:
 *   {
 *     "mcpServers": {
 *       "agentaudit": {
 *         "command": "node",
 *         "args": ["path/to/agentaudit/mcp-server/index.mjs"]
 *       }
 *     }
 *   }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_DIR = path.resolve(__dirname, '..');
const REGISTRY_URL = 'https://agentaudit.dev';
const MAX_FILE_SIZE = 50_000; // 50KB per file
const MAX_TOTAL_SIZE = 300_000; // 300KB total code
const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', 'build',
  '.next', '.nuxt', 'coverage', '.pytest_cache', '.mypy_cache', 'vendor',
  'test', 'tests', '__tests__', 'spec', 'specs', 'docs', 'doc',
  'examples', 'example', 'fixtures', '.github', '.vscode', '.idea',
  'e2e', 'benchmark', 'benchmarks', '.tox', '.eggs', 'htmlcov',
]);
const SKIP_EXTENSIONS = new Set([
  '.lock', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
  '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.tar', '.gz',
  '.map', '.min.js', '.min.css', '.d.ts', '.pyc', '.pyo', '.so',
  '.dylib', '.dll', '.exe', '.bin', '.dat', '.db', '.sqlite',
]);
const PRIORITY_FILES = [
  'index.js', 'index.ts', 'index.mjs', 'main.js', 'main.ts', 'main.py',
  'app.js', 'app.ts', 'app.py', 'server.js', 'server.ts', 'server.py',
  'cli.js', 'cli.ts', 'cli.py', '__init__.py', '__main__.py',
  'package.json', 'pyproject.toml', 'setup.py', 'setup.cfg',
  'Cargo.toml', 'go.mod', 'SKILL.md', 'skill.md',
  'Makefile', 'Dockerfile', 'docker-compose.yml',
];

// ── Helpers ──────────────────────────────────────────────

function loadApiKey() {
  if (process.env.AGENTAUDIT_API_KEY) return process.env.AGENTAUDIT_API_KEY;
  const credPath = path.join(SKILL_DIR, 'config', 'credentials.json');
  if (fs.existsSync(credPath)) {
    try {
      return JSON.parse(fs.readFileSync(credPath, 'utf8')).api_key || '';
    } catch { return ''; }
  }
  return '';
}

function loadAuditPrompt() {
  const promptPath = path.join(SKILL_DIR, 'prompts', 'audit-prompt.md');
  if (fs.existsSync(promptPath)) {
    return fs.readFileSync(promptPath, 'utf8');
  }
  return 'ERROR: audit-prompt.md not found at ' + promptPath;
}

function collectFiles(dir, basePath = '', collected = [], totalSize = { bytes: 0 }) {
  if (totalSize.bytes >= MAX_TOTAL_SIZE) return collected;
  
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return collected; }
  
  // Sort: priority files first
  entries.sort((a, b) => {
    const aP = PRIORITY_FILES.includes(a.name) ? 0 : 1;
    const bP = PRIORITY_FILES.includes(b.name) ? 0 : 1;
    return aP - bP || a.name.localeCompare(b.name);
  });
  
  for (const entry of entries) {
    if (totalSize.bytes >= MAX_TOTAL_SIZE) break;
    
    const relPath = basePath ? `${basePath}/${entry.name}` : entry.name;
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      collectFiles(fullPath, relPath, collected, totalSize);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) continue;
      
      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE) {
          collected.push({ path: relPath, content: `[FILE TOO LARGE: ${stat.size} bytes — skipped]` });
          continue;
        }
        if (stat.size === 0) continue;
        
        const content = fs.readFileSync(fullPath, 'utf8');
        totalSize.bytes += content.length;
        collected.push({ path: relPath, content });
      } catch {
        // Binary or unreadable — skip
      }
    }
  }
  return collected;
}

function cloneRepo(sourceUrl) {
  const tmpDir = fs.mkdtempSync('/tmp/agentaudit-');
  try {
    execSync(`git clone --depth 1 "${sourceUrl}" "${tmpDir}/repo" 2>/dev/null`, {
      timeout: 30_000,
      stdio: 'pipe',
    });
    return path.join(tmpDir, 'repo');
  } catch (err) {
    throw new Error(`Failed to clone ${sourceUrl}: ${err.message}`);
  }
}

function cleanupRepo(repoPath) {
  try {
    execSync(`rm -rf "${path.dirname(repoPath)}"`, { stdio: 'pipe' });
  } catch {}
}

function slugFromUrl(url) {
  // https://github.com/owner/repo → owner-repo or just repo
  const match = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (match) return match[2].toLowerCase().replace(/[^a-z0-9-]/g, '-');
  return url.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 60);
}

// ── MCP Server ───────────────────────────────────────────

const server = new Server(
  { name: 'agentaudit', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'audit_package',
      description: 'Clone a repository and prepare it for security audit. Returns the source code and audit instructions. You (the agent) then analyze the code following the audit prompt and call submit_report with the results.',
      inputSchema: {
        type: 'object',
        properties: {
          source_url: {
            type: 'string',
            description: 'Git repository URL to audit (e.g., https://github.com/owner/repo)',
          },
        },
        required: ['source_url'],
      },
    },
    {
      name: 'submit_report',
      description: 'Submit a completed security audit report to the AgentAudit registry (agentaudit.dev). Call this after you have analyzed the code from audit_package.',
      inputSchema: {
        type: 'object',
        properties: {
          report: {
            type: 'object',
            description: 'The audit report JSON object. Must include: skill_slug, source_url, risk_score (0-100), result (safe|caution|unsafe), findings (array), findings_count, max_severity.',
          },
        },
        required: ['report'],
      },
    },
    {
      name: 'check_package',
      description: 'Look up a package in the AgentAudit security registry. Returns the latest audit results if available.',
      inputSchema: {
        type: 'object',
        properties: {
          package_name: {
            type: 'string',
            description: 'Package name or slug to look up (e.g., "fastmcp", "mongodb-mcp-server")',
          },
        },
        required: ['package_name'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  switch (name) {
    case 'audit_package': {
      const { source_url } = args;
      if (!source_url || !source_url.startsWith('http')) {
        return { content: [{ type: 'text', text: 'Error: source_url must be a valid HTTP(S) URL' }] };
      }
      
      let repoPath;
      try {
        repoPath = cloneRepo(source_url);
        const files = collectFiles(repoPath);
        const slug = slugFromUrl(source_url);
        const auditPrompt = loadAuditPrompt();
        
        // Build the response
        let codeBlock = '';
        for (const file of files) {
          codeBlock += `\n### FILE: ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n`;
        }
        
        const response = [
          `# Security Audit Request`,
          ``,
          `**Package:** ${slug}`,
          `**Source:** ${source_url}`,
          `**Files collected:** ${files.length}`,
          ``,
          `## Instructions`,
          ``,
          `Analyze the source code below following the audit methodology. After your analysis, call the \`submit_report\` tool with your findings as a JSON object.`,
          ``,
          `The report JSON must include:`,
          '```json',
          `{`,
          `  "skill_slug": "${slug}",`,
          `  "source_url": "${source_url}",`,
          `  "package_type": "<mcp-server|agent-skill|library|cli-tool>",`,
          `  "risk_score": <0-100>,`,
          `  "result": "<safe|caution|unsafe>",`,
          `  "max_severity": "<none|low|medium|high|critical>",`,
          `  "findings_count": <number>,`,
          `  "findings": [`,
          `    {`,
          `      "id": "FINDING_ID",`,
          `      "title": "Short title",`,
          `      "severity": "<low|medium|high|critical>",`,
          `      "category": "<category>",`,
          `      "description": "Detailed description",`,
          `      "file": "path/to/file.js",`,
          `      "line": <line_number>,`,
          `      "remediation": "How to fix",`,
          `      "confidence": "<low|medium|high>",`,
          `      "is_by_design": <true|false>`,
          `    }`,
          `  ]`,
          `}`,
          '```',
          ``,
          `## Audit Methodology`,
          ``,
          auditPrompt,
          ``,
          `## Source Code`,
          ``,
          codeBlock,
        ].join('\n');
        
        return { content: [{ type: 'text', text: response }] };
      } catch (err) {
        return { content: [{ type: 'text', text: `Error: ${err.message}` }] };
      } finally {
        if (repoPath) cleanupRepo(repoPath);
      }
    }
    
    case 'submit_report': {
      const { report } = args;
      if (!report || typeof report !== 'object') {
        return { content: [{ type: 'text', text: 'Error: report must be a JSON object' }] };
      }
      
      const apiKey = loadApiKey();
      if (!apiKey) {
        return { content: [{ type: 'text', text: 'Error: No API key configured. Set AGENTAUDIT_API_KEY or register first.' }] };
      }
      
      // Validate required fields
      const required = ['skill_slug', 'source_url', 'risk_score', 'result'];
      for (const field of required) {
        if (report[field] == null) {
          return { content: [{ type: 'text', text: `Error: Missing required field "${field}" in report` }] };
        }
      }
      
      // Auto-fix findings
      if (!Array.isArray(report.findings)) report.findings = [];
      report.findings_count = report.findings.length;
      if (!report.max_severity) {
        const severities = ['critical', 'high', 'medium', 'low', 'none'];
        report.max_severity = report.findings.reduce((max, f) => {
          const fi = severities.indexOf(f.severity);
          const mi = severities.indexOf(max);
          return fi < mi ? f.severity : max;
        }, 'none');
      }
      
      try {
        const res = await fetch(`${REGISTRY_URL}/api/reports`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(report),
          signal: AbortSignal.timeout(60_000),
        });
        
        const body = await res.text();
        let data;
        try { data = JSON.parse(body); } catch { data = { raw: body }; }
        
        if (res.ok) {
          return { content: [{ type: 'text', text: `Report submitted successfully!\nReport ID: ${data.report_id || 'unknown'}\nURL: ${REGISTRY_URL}/skills/${report.skill_slug}\n\n${JSON.stringify(data, null, 2)}` }] };
        } else {
          return { content: [{ type: 'text', text: `Upload failed (HTTP ${res.status}): ${JSON.stringify(data, null, 2)}` }] };
        }
      } catch (err) {
        return { content: [{ type: 'text', text: `Upload error: ${err.message}` }] };
      }
    }
    
    case 'check_package': {
      const { package_name } = args;
      if (!package_name) {
        return { content: [{ type: 'text', text: 'Error: package_name is required' }] };
      }
      
      try {
        const res = await fetch(`${REGISTRY_URL}/api/skills/${encodeURIComponent(package_name)}`, {
          signal: AbortSignal.timeout(10_000),
        });
        
        if (res.status === 404) {
          return { content: [{ type: 'text', text: `Package "${package_name}" not found in registry. It may not have been audited yet. Use audit_package to audit it.` }] };
        }
        
        const data = await res.json();
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (err) {
        return { content: [{ type: 'text', text: `Registry lookup failed: ${err.message}` }] };
      }
    }
    
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
  }
});

// ── Start ────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
