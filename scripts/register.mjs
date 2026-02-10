#!/usr/bin/env node
/**
 * register.mjs — Cross-platform agent registration for AgentAudit
 * Works on Windows, macOS, and Linux. No bash/jq required.
 *
 * Usage:
 *   node scripts/register.mjs <agent-name>
 *
 * Creates credentials at:
 *   - <skill-dir>/config/credentials.json (skill-local)
 *   - ~/.config/agentaudit/credentials.json (user-level backup)
 *
 * Requires: Node.js 18+ (for built-in fetch)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const API_URL = 'https://www.agentaudit.dev';

// ── Args ─────────────────────────────────────────────────

const agentName = process.argv[2];
if (!agentName) {
  console.error('Usage: node scripts/register.mjs <agent-name>');
  console.error('Example: node scripts/register.mjs my-security-bot');
  process.exit(1);
}

// ── Check existing key ───────────────────────────────────

const skillCredDir = path.join(__dirname, '..', 'config');
const skillCredFile = path.join(skillCredDir, 'credentials.json');

if (fs.existsSync(skillCredFile)) {
  try {
    const existing = JSON.parse(fs.readFileSync(skillCredFile, 'utf8'));
    if (existing.api_key) {
      console.log(`Already registered as "${existing.agent_name || 'unknown'}".`);
      console.log(`API key exists at: ${skillCredFile}`);
      console.log('To rotate your key: node scripts/rotate-key.mjs');
      console.log('To re-register: delete the config/credentials.json file first.');
      process.exit(0);
    }
  } catch {}
}

const home = process.env.HOME || process.env.USERPROFILE || '';
const xdg = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
const userCredDir = path.join(xdg, 'agentaudit');
const userCredFile = path.join(userCredDir, 'credentials.json');

if (fs.existsSync(userCredFile)) {
  try {
    const existing = JSON.parse(fs.readFileSync(userCredFile, 'utf8'));
    if (existing.api_key) {
      console.log(`Found existing key in user config: ${userCredFile}`);
      console.log('Copying to skill-local config...');
      fs.mkdirSync(skillCredDir, { recursive: true });
      fs.writeFileSync(skillCredFile, JSON.stringify({ api_key: existing.api_key, agent_name: existing.agent_name }, null, 2));
      console.log('Done! Both credential files are now in sync.');
      process.exit(0);
    }
  } catch {}
}

// ── Register ─────────────────────────────────────────────

console.log(`Registering agent "${agentName}" at ${API_URL}...`);

let res;
try {
  res = await fetch(`${API_URL}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_name: agentName }),
    signal: AbortSignal.timeout(15_000),
  });
} catch (err) {
  console.error(`Registration failed: ${err.message}`);
  process.exit(1);
}

if (!res.ok) {
  const text = await res.text();
  console.error(`Registration failed (HTTP ${res.status}): ${text}`);
  process.exit(1);
}

const data = await res.json();
const cred = { api_key: data.api_key, agent_name: data.agent_name };

// Save to skill-local
fs.mkdirSync(skillCredDir, { recursive: true });
fs.writeFileSync(skillCredFile, JSON.stringify(cred, null, 2));
console.log(`Saved to: ${skillCredFile}`);

// Save to user-level backup
try {
  fs.mkdirSync(userCredDir, { recursive: true });
  fs.writeFileSync(userCredFile, JSON.stringify(cred, null, 2));
  console.log(`Backup saved to: ${userCredFile}`);
} catch (err) {
  console.log(`Could not save user-level backup: ${err.message}`);
}

console.log('');
console.log(`Registered as: ${data.agent_name}`);
console.log('You can now use gate.mjs and upload.mjs.');
