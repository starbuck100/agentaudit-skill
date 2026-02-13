#!/usr/bin/env node
/**
 * AgentAudit CLI — Beautiful terminal output for security audits
 * 
 * Usage:
 *   agentaudit setup                              Interactive setup (register + API key)
 *   agentaudit scan <repo-url> [repo-url...]       Scan repositories
 *   agentaudit check <package-name>                Look up in registry
 * 
 * Examples:
 *   agentaudit setup
 *   agentaudit scan https://github.com/owner/repo
 *   agentaudit scan repo1 repo2 repo3
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createInterface } from 'readline';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_DIR = path.resolve(__dirname, '..');
const REGISTRY_URL = 'https://agentaudit.dev';

// ── ANSI Colors ──────────────────────────────────────────

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

const icons = {
  safe: `${c.green}✔${c.reset}`,
  caution: `${c.yellow}⚠${c.reset}`,
  unsafe: `${c.red}✖${c.reset}`,
  info: `${c.blue}ℹ${c.reset}`,
  scan: `${c.cyan}◉${c.reset}`,
  tree: `${c.gray}├──${c.reset}`,
  treeLast: `${c.gray}└──${c.reset}`,
  pipe: `${c.gray}│${c.reset}`,
  bullet: `${c.gray}•${c.reset}`,
};

// ── Credentials ─────────────────────────────────────────

const home = process.env.HOME || process.env.USERPROFILE || '';
const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
const USER_CRED_DIR = path.join(xdgConfig, 'agentaudit');
const USER_CRED_FILE = path.join(USER_CRED_DIR, 'credentials.json');
const SKILL_CRED_FILE = path.join(SKILL_DIR, 'config', 'credentials.json');

function loadCredentials() {
  for (const f of [SKILL_CRED_FILE, USER_CRED_FILE]) {
    if (fs.existsSync(f)) {
      try {
        const data = JSON.parse(fs.readFileSync(f, 'utf8'));
        if (data.api_key) return data;
      } catch {}
    }
  }
  if (process.env.AGENTAUDIT_API_KEY) {
    return { api_key: process.env.AGENTAUDIT_API_KEY, agent_name: 'env' };
  }
  return null;
}

function saveCredentials(data) {
  const json = JSON.stringify(data, null, 2);
  fs.mkdirSync(USER_CRED_DIR, { recursive: true });
  fs.writeFileSync(USER_CRED_FILE, json, { mode: 0o600 });
  try {
    fs.mkdirSync(path.dirname(SKILL_CRED_FILE), { recursive: true });
    fs.writeFileSync(SKILL_CRED_FILE, json, { mode: 0o600 });
  } catch {}
}

function askQuestion(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

async function registerAgent(agentName) {
  const res = await fetch(`${REGISTRY_URL}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_name: agentName }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`Registration failed (HTTP ${res.status}): ${await res.text()}`);
  return res.json();
}

async function setupCommand() {
  console.log(`  ${c.bold}Setup${c.reset}`);
  console.log();

  const existing = loadCredentials();
  if (existing) {
    console.log(`  ${icons.safe}  Already configured as ${c.bold}${existing.agent_name}${c.reset}`);
    console.log(`  ${c.dim}Key: ${existing.api_key.slice(0, 8)}...${c.reset}`);
    console.log();
    const answer = await askQuestion(`  Reconfigure? ${c.dim}(y/N)${c.reset} `);
    if (answer.toLowerCase() !== 'y') {
      console.log(`  ${c.dim}Keeping existing config.${c.reset}`);
      return;
    }
    console.log();
  }

  console.log(`  ${c.bold}1)${c.reset} Register new agent ${c.dim}(free, creates API key automatically)${c.reset}`);
  console.log(`  ${c.bold}2)${c.reset} Enter existing API key`);
  console.log();
  const choice = await askQuestion(`  Choice ${c.dim}(1/2)${c.reset}: `);
  console.log();

  if (choice === '2') {
    const key = await askQuestion(`  API Key: `);
    if (!key) { console.log(`  ${c.red}No key entered.${c.reset}`); return; }
    const name = await askQuestion(`  Agent name ${c.dim}(optional)${c.reset}: `);
    saveCredentials({ api_key: key, agent_name: name || 'custom' });
    console.log();
    console.log(`  ${icons.safe}  Saved! Key stored in ${c.dim}${USER_CRED_FILE}${c.reset}`);
  } else {
    const name = await askQuestion(`  Agent name ${c.dim}(e.g. my-scanner, claude-desktop)${c.reset}: `);
    if (!name || !/^[a-zA-Z0-9._-]{2,64}$/.test(name)) {
      console.log(`  ${c.red}Invalid name. Use 2-64 chars: letters, numbers, dash, underscore, dot.${c.reset}`);
      return;
    }
    process.stdout.write(`  Registering ${c.bold}${name}${c.reset}...`);
    try {
      const data = await registerAgent(name);
      saveCredentials({ api_key: data.api_key, agent_name: data.agent_name });
      console.log(` ${c.green}done!${c.reset}`);
      console.log();
      console.log(`  ${icons.safe}  Registered as ${c.bold}${data.agent_name}${c.reset}`);
      console.log(`  ${c.dim}Key: ${data.api_key.slice(0, 12)}...${c.reset}`);
      console.log(`  ${c.dim}Saved to: ${USER_CRED_FILE}${c.reset}`);
    } catch (err) {
      console.log(` ${c.red}failed${c.reset}`);
      console.log(`  ${c.red}${err.message}${c.reset}`);
      return;
    }
  }

  console.log();
  console.log(`  ${c.bold}Ready!${c.reset} You can now:`);
  console.log(`  ${c.dim}•${c.reset} Scan packages:  ${c.cyan}agentaudit scan <repo-url>${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Check registry:  ${c.cyan}agentaudit check <name>${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Submit reports via MCP in Claude/Cursor/Windsurf`);
  console.log();
}

// ── Helpers ──────────────────────────────────────────────

function banner() {
  console.log();
  console.log(`  ${c.bold}${c.cyan}AgentAudit${c.reset} ${c.dim}v1.0.0${c.reset}`);
  console.log(`  ${c.dim}Security scanner for AI packages${c.reset}`);
  console.log();
}

function slugFromUrl(url) {
  const match = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (match) return match[2].toLowerCase().replace(/[^a-z0-9-]/g, '-');
  return url.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 60);
}

function elapsed(startMs) {
  const ms = Date.now() - startMs;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function riskBadge(score) {
  if (score === 0) return `${c.bgGreen}${c.bold}${c.white} SAFE ${c.reset}`;
  if (score <= 10) return `${c.bgGreen}${c.white} LOW ${c.reset}`;
  if (score <= 30) return `${c.bgYellow}${c.bold} CAUTION ${c.reset}`;
  return `${c.bgRed}${c.bold}${c.white} UNSAFE ${c.reset}`;
}

function severityColor(sev) {
  switch (sev) {
    case 'critical': return c.red;
    case 'high': return c.red;
    case 'medium': return c.yellow;
    case 'low': return c.blue;
    default: return c.gray;
  }
}

function severityIcon(sev) {
  switch (sev) {
    case 'critical': return `${c.red}●${c.reset}`;
    case 'high': return `${c.red}●${c.reset}`;
    case 'medium': return `${c.yellow}●${c.reset}`;
    case 'low': return `${c.blue}●${c.reset}`;
    default: return `${c.green}●${c.reset}`;
  }
}

// ── File Collection (same logic as MCP server) ──────────

const MAX_FILE_SIZE = 50_000;
const MAX_TOTAL_SIZE = 300_000;
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

function collectFiles(dir, basePath = '', collected = [], totalSize = { bytes: 0 }) {
  if (totalSize.bytes >= MAX_TOTAL_SIZE) return collected;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return collected; }
  entries.sort((a, b) => a.name.localeCompare(b.name));
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
        if (stat.size > MAX_FILE_SIZE || stat.size === 0) continue;
        const content = fs.readFileSync(fullPath, 'utf8');
        totalSize.bytes += content.length;
        collected.push({ path: relPath, content, size: stat.size });
      } catch {}
    }
  }
  return collected;
}

// ── Detect package properties ───────────────────────────

function detectPackageInfo(repoPath, files) {
  const info = { type: 'unknown', tools: [], prompts: [], language: 'unknown', entrypoint: null };
  
  // Detect language
  const exts = files.map(f => path.extname(f.path).toLowerCase());
  const extCounts = {};
  exts.forEach(e => { extCounts[e] = (extCounts[e] || 0) + 1; });
  const topExt = Object.entries(extCounts).sort((a, b) => b[1] - a[1])[0]?.[0];
  
  const langMap = { '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.mjs': 'JavaScript', '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.rb': 'Ruby' };
  info.language = langMap[topExt] || topExt || 'unknown';
  
  // Detect package type
  const allContent = files.map(f => f.content).join('\n');
  if (allContent.includes('@modelcontextprotocol') || allContent.includes('FastMCP') || allContent.includes('mcp.server') || allContent.includes('mcp_server')) {
    info.type = 'mcp-server';
  } else if (files.some(f => f.path.toLowerCase() === 'skill.md')) {
    info.type = 'agent-skill';
  } else if (allContent.includes('#!/usr/bin/env') || allContent.includes('argparse') || allContent.includes('commander')) {
    info.type = 'cli-tool';
  } else {
    info.type = 'library';
  }
  
  // Extract MCP tools (look for tool definitions)
  const toolPatterns = [
    // JS/TS: name: 'tool_name' or "tool_name" in tool definitions
    /(?:name|tool_name)['":\s]+['"]([a-z_][a-z0-9_]*)['"]/gi,
    // Python: @mcp.tool() def func_name or Tool(name="...")
    /(?:@(?:mcp|server)\.tool\(\)[\s\S]*?def\s+([a-z_][a-z0-9_]*))|(?:Tool\s*\(\s*name\s*=\s*['"]([a-z_][a-z0-9_]*)['"])/gi,
    // Direct: tool names in ListTools handlers
    /['"]name['"]\s*:\s*['"]([a-z_][a-z0-9_]*)['"]/gi,
  ];
  
  const toolSet = new Set();
  for (const file of files) {
    for (const pattern of toolPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(file.content)) !== null) {
        const name = m[1] || m[2];
        if (name && name.length > 2 && name.length < 50 && !['type', 'name', 'string', 'object', 'number', 'boolean', 'array', 'required', 'description', 'default', 'null', 'true', 'false', 'none'].includes(name)) {
          toolSet.add(name);
        }
      }
    }
  }
  info.tools = [...toolSet];
  
  // Extract prompts (look for prompt definitions)
  const promptPatterns = [
    /(?:prompt|PROMPT)['":\s]+['"]([a-z_][a-z0-9_]*)['"]/gi,
    /@(?:mcp|server)\.prompt\(\)[\s\S]*?def\s+([a-z_][a-z0-9_]*)/gi,
  ];
  const promptSet = new Set();
  for (const file of files) {
    for (const pattern of promptPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(file.content)) !== null) {
        if (m[1] && m[1].length > 2) promptSet.add(m[1]);
      }
    }
  }
  info.prompts = [...promptSet];
  
  // Detect entrypoint
  const entryFiles = ['index.js', 'index.ts', 'index.mjs', 'main.py', 'server.py', 'app.py', 'src/index.ts', 'src/main.ts', 'src/index.js'];
  for (const ef of entryFiles) {
    if (files.some(f => f.path === ef)) { info.entrypoint = ef; break; }
  }
  
  return info;
}

// ── Quick static checks ─────────────────────────────────

function quickChecks(files) {
  const findings = [];
  
  const checks = [
    {
      id: 'EXEC_INJECTION',
      title: 'Command injection risk',
      severity: 'high',
      pattern: /(?:exec(?:Sync)?|spawn|child_process|subprocess|os\.system|os\.popen|Popen)\s*\([^)]*(?:\$\{|`|\+\s*(?:req|input|args|param|user|query))/i,
      category: 'injection',
    },
    {
      id: 'EVAL_USAGE',
      title: 'Dynamic code evaluation',
      severity: 'high',
      pattern: /(?:^|[^a-z])eval\s*\([^)]*(?:input|req|user|param|arg|query)/im,
      category: 'injection',
    },
    {
      id: 'HARDCODED_SECRET',
      title: 'Potential hardcoded secret',
      severity: 'medium',
      pattern: /(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{16,}['"]/i,
      category: 'secrets',
    },
    {
      id: 'SSL_DISABLED',
      title: 'SSL/TLS verification disabled',
      severity: 'medium',
      pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|VERIFY_SSL\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureRequestWarning)/i,
      category: 'crypto',
    },
    {
      id: 'PATH_TRAVERSAL',
      title: 'Potential path traversal',
      severity: 'medium',
      pattern: /(?:\.\.\/|\.\.\\|path\.join|os\.path\.join)\s*\([^)]*(?:input|req|user|param|arg|query)/i,
      category: 'filesystem',
    },
    {
      id: 'CORS_WILDCARD',
      title: 'Wildcard CORS origin',
      severity: 'low',
      pattern: /(?:Access-Control-Allow-Origin|cors)\s*[:({]\s*['"]\*/i,
      category: 'network',
    },
    {
      id: 'TELEMETRY',
      title: 'Undisclosed telemetry',
      severity: 'low',
      pattern: /(?:posthog|mixpanel|analytics|telemetry|tracking|sentry).*(?:init|setup|track|capture)/i,
      category: 'privacy',
    },
    {
      id: 'SHELL_EXEC',
      title: 'Shell command execution',
      severity: 'high',
      pattern: /(?:subprocess\.(?:run|call|Popen)|os\.system|os\.popen|execSync|child_process\.exec)\s*\(/i,
      category: 'injection',
    },
    {
      id: 'SQL_INJECTION',
      title: 'Potential SQL injection',
      severity: 'high',
      pattern: /(?:execute|query|raw)\s*\(\s*(?:f['"]|['"].*?%s|['"].*?\{|['"].*?\+)/i,
      category: 'injection',
    },
    {
      id: 'YAML_UNSAFE',
      title: 'Unsafe YAML loading',
      severity: 'medium',
      pattern: /yaml\.(?:load|unsafe_load)\s*\(/i,
      category: 'deserialization',
    },
    {
      id: 'PICKLE_LOAD',
      title: 'Unsafe deserialization (pickle)',
      severity: 'high',
      pattern: /pickle\.loads?\s*\(/i,
      category: 'deserialization',
    },
    {
      id: 'PROMPT_INJECTION',
      title: 'Prompt injection vector',
      severity: 'high',
      pattern: /(?:<IMPORTANT>|<SYSTEM>|ignore previous|you are now|new instructions)/i,
      category: 'prompt-injection',
    },
  ];
  
  for (const file of files) {
    for (const check of checks) {
      const match = check.pattern.exec(file.content);
      if (match) {
        // Find line number
        const lines = file.content.slice(0, match.index).split('\n');
        findings.push({
          ...check,
          file: file.path,
          line: lines.length,
          snippet: match[0].trim().slice(0, 80),
          confidence: 'medium',
        });
      }
    }
  }
  
  return findings;
}

// ── Registry check ──────────────────────────────────────

async function checkRegistry(slug) {
  try {
    const res = await fetch(`${REGISTRY_URL}/api/skills/${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

// ── Print results ───────────────────────────────────────

function printScanResult(url, info, files, findings, registryData, duration) {
  const slug = slugFromUrl(url);
  
  // Header
  console.log(`${icons.scan}  ${c.bold}${slug}${c.reset}  ${c.dim}${url}${c.reset}`);
  console.log(`${icons.pipe}  ${c.dim}${info.language} ${info.type}${c.reset}  ${c.dim}${files.length} files scanned in ${duration}${c.reset}`);
  
  // Tools & prompts tree
  const items = [
    ...info.tools.map(t => ({ kind: 'tool', name: t })),
    ...info.prompts.map(p => ({ kind: 'prompt', name: p })),
  ];
  
  if (items.length > 0) {
    console.log(`${icons.pipe}`);
    for (let i = 0; i < items.length; i++) {
      const isLast = i === items.length - 1 && findings.length === 0;
      const branch = isLast ? icons.treeLast : icons.tree;
      const item = items[i];
      const kindLabel = item.kind === 'tool' ? `${c.dim}tool${c.reset}  ` : `${c.dim}prompt${c.reset}`;
      const padName = item.name.padEnd(28);
      
      // Check if this tool has a finding associated
      const toolFinding = findings.find(f => 
        f.snippet && f.snippet.toLowerCase().includes(item.name.toLowerCase())
      );
      
      if (toolFinding) {
        const sc = severityColor(toolFinding.severity);
        console.log(`${branch}  ${kindLabel}  ${c.bold}${padName}${c.reset} ${sc}⚠ flagged${c.reset} — ${toolFinding.title}`);
      } else {
        console.log(`${branch}  ${kindLabel}  ${c.bold}${padName}${c.reset} ${c.green}✔ ok${c.reset}`);
      }
    }
  } else {
    console.log(`${icons.pipe}  ${c.dim}(no tools or prompts detected)${c.reset}`);
  }
  
  // Findings
  if (findings.length > 0) {
    console.log(`${icons.pipe}`);
    console.log(`${icons.pipe}  ${c.bold}Findings (${findings.length})${c.reset}  ${c.dim}static analysis — may include false positives${c.reset}`);
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const isLast = i === findings.length - 1;
      const branch = isLast ? icons.treeLast : icons.tree;
      const pipeOrSpace = isLast ? '   ' : `${icons.pipe}  `;
      const sc = severityColor(f.severity);
      console.log(`${branch}  ${severityIcon(f.severity)} ${sc}${f.severity.toUpperCase().padEnd(8)}${c.reset} ${f.title}`);
      console.log(`${pipeOrSpace}   ${c.dim}${f.file}:${f.line}${c.reset}  ${c.dim}${f.snippet || ''}${c.reset}`);
    }
  }
  
  // Registry status
  console.log(`${icons.pipe}`);
  if (registryData) {
    const rd = registryData;
    const riskScore = rd.risk_score ?? rd.latest_risk_score ?? 0;
    console.log(`${icons.treeLast}  ${c.dim}registry${c.reset}  ${riskBadge(riskScore)} Risk ${riskScore}  ${c.dim}${REGISTRY_URL}/skills/${slug}${c.reset}`);
  } else {
    console.log(`${icons.treeLast}  ${c.dim}registry${c.reset}  ${c.dim}not audited yet${c.reset}`);
  }
  
  console.log();
}

function printSummary(results) {
  const total = results.length;
  const safe = results.filter(r => r.findings.length === 0).length;
  const withFindings = total - safe;
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  
  console.log(`${c.dim}${'─'.repeat(60)}${c.reset}`);
  console.log(`  ${c.bold}Summary${c.reset}  ${total} packages scanned`);
  console.log();
  if (safe > 0) console.log(`  ${icons.safe}  ${c.green}${safe} clean${c.reset}`);
  if (withFindings > 0) console.log(`  ${icons.caution}  ${c.yellow}${withFindings} with findings${c.reset} (${totalFindings} total)`);
  
  // Breakdown by severity
  const bySev = {};
  results.forEach(r => r.findings.forEach(f => {
    bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  }));
  if (Object.keys(bySev).length > 0) {
    console.log();
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      if (bySev[sev]) {
        console.log(`    ${severityIcon(sev)} ${bySev[sev]}× ${severityColor(sev)}${sev}${c.reset}`);
      }
    }
  }
  
  console.log();
}

// ── Clone & Scan ────────────────────────────────────────

async function scanRepo(url) {
  const start = Date.now();
  const slug = slugFromUrl(url);
  
  process.stdout.write(`${icons.scan}  Scanning ${c.bold}${slug}${c.reset} ${c.dim}...${c.reset}`);
  
  // Clone
  const tmpDir = fs.mkdtempSync('/tmp/agentaudit-');
  const repoPath = path.join(tmpDir, 'repo');
  try {
    execSync(`git clone --depth 1 "${url}" "${repoPath}" 2>/dev/null`, {
      timeout: 30_000,
      stdio: 'pipe',
    });
  } catch (err) {
    process.stdout.write(`  ${c.red}✖ clone failed${c.reset}\n`);
    return null;
  }
  
  // Collect files
  const files = collectFiles(repoPath);
  
  // Detect info
  const info = detectPackageInfo(repoPath, files);
  
  // Quick checks
  const findings = quickChecks(files);
  
  // Registry lookup
  const registryData = await checkRegistry(slug);
  
  // Cleanup
  try { execSync(`rm -rf "${tmpDir}"`, { stdio: 'pipe' }); } catch {}
  
  const duration = elapsed(start);
  
  // Clear the "Scanning..." line
  process.stdout.write('\r\x1b[K');
  
  // Print result
  printScanResult(url, info, files, findings, registryData, duration);
  
  return { slug, url, info, files: files.length, findings, registryData, duration };
}

// ── Check command ───────────────────────────────────────

async function checkPackage(name) {
  console.log(`${icons.info}  Looking up ${c.bold}${name}${c.reset} in registry...`);
  console.log();
  
  const data = await checkRegistry(name);
  if (!data) {
    console.log(`  ${c.yellow}Not found${c.reset} — package "${name}" hasn't been audited yet.`);
    console.log(`  ${c.dim}Run: agentaudit scan <repo-url> to audit it${c.reset}`);
    return;
  }
  
  const riskScore = data.risk_score ?? data.latest_risk_score ?? 0;
  console.log(`  ${c.bold}${name}${c.reset}  ${riskBadge(riskScore)}`);
  console.log(`  ${c.dim}Risk Score: ${riskScore}/100${c.reset}`);
  if (data.source_url) console.log(`  ${c.dim}Source: ${data.source_url}${c.reset}`);
  console.log(`  ${c.dim}Registry: ${REGISTRY_URL}/skills/${name}${c.reset}`);
  if (data.has_official_audit) console.log(`  ${c.green}✔ Officially audited${c.reset}`);
  console.log();
}

// ── Main ────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    banner();
    console.log(`  ${c.bold}Usage:${c.reset}`);
    console.log(`    agentaudit setup                            Register + configure API key`);
    console.log(`    agentaudit scan <repo-url> [repo-url...]    Scan repositories`);
    console.log(`    agentaudit check <package-name>             Look up in registry`);
    console.log();
    console.log(`  ${c.bold}Examples:${c.reset}`);
    console.log(`    agentaudit setup`);
    console.log(`    agentaudit scan https://github.com/owner/repo`);
    console.log(`    agentaudit scan repo1.git repo2.git repo3.git`);
    console.log(`    agentaudit check fastmcp`);
    console.log();
    process.exit(0);
  }
  
  const command = args[0];
  const targets = args.slice(1);
  
  banner();
  
  if (command === 'setup') {
    await setupCommand();
    return;
  }
  
  if (command === 'check') {
    if (targets.length === 0) {
      console.log(`  ${c.red}Error: package name required${c.reset}`);
      process.exit(1);
    }
    for (const t of targets) await checkPackage(t);
    return;
  }
  
  if (command === 'scan') {
    if (targets.length === 0) {
      console.log(`  ${c.red}Error: at least one repository URL required${c.reset}`);
      process.exit(1);
    }
    
    const results = [];
    for (const url of targets) {
      const result = await scanRepo(url);
      if (result) results.push(result);
    }
    
    if (results.length > 1) {
      printSummary(results);
    }
    return;
  }
  
  console.log(`  ${c.red}Unknown command: ${command}${c.reset}`);
  console.log(`  ${c.dim}Run agentaudit --help for usage${c.reset}`);
  process.exit(1);
}

main().catch(err => {
  console.error(`${c.red}Error: ${err.message}${c.reset}`);
  process.exit(1);
});
