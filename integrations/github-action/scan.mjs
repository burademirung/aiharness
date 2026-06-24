#!/usr/bin/env node
// AIHarness CI scan — Node 20 ESM, zero runtime dependencies.
// All configuration is read from environment variables set by action.yml.

import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import process from 'node:process';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_URL        = (process.env.AIHARNESS_API_URL || 'https://aiharness.degenito.ai').replace(/\/$/, '');
const API_KEY        = process.env.AIHARNESS_API_KEY  || '';
const LANGUAGE       = process.env.AIHARNESS_LANGUAGE || 'python';
const PATHS_RAW      = process.env.AIHARNESS_PATHS    || '.';
const FAIL_SEVERITY  = (process.env.AIHARNESS_FAIL_ON_SEVERITY || 'high').toLowerCase();
const MAX_FILES      = parseInt(process.env.AIHARNESS_MAX_FILES || '50', 10);
const SARIF_FILE     = process.env.AIHARNESS_SARIF_FILE || 'aiharness.sarif';
const WORKSPACE      = process.env.GITHUB_WORKSPACE || process.cwd();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALLOWED_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx',
  '.java', '.go', '.rb', '.php',
  '.c', '.cpp', '.cs', '.rs',
]);

const SKIP_DIRS = new Set([
  'node_modules', 'vendor', 'dist', 'build', '.git',
  '__pycache__', '.venv', 'venv', 'env',
  '.mypy_cache', '.pytest_cache', 'coverage',
]);

const MAX_FILE_BYTES    = 256 * 1024; // 256 KB per file
const POLL_INTERVAL_MS  = 2_000;
const POLL_TIMEOUT_MS   = 5 * 60 * 1_000; // 5 minutes

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none'];

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/**
 * Walk a directory tree and collect source files up to the caps.
 * @param {string} dir  Absolute path to traverse.
 * @param {string[]} collected  Accumulator.
 */
function walkDir(dir, collected) {
  if (collected.length >= MAX_FILES) return;

  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable — skip silently
  }

  for (const entry of entries) {
    if (collected.length >= MAX_FILES) break;
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        walkDir(fullPath, collected);
      }
    } else if (entry.isFile()) {
      if (ALLOWED_EXTENSIONS.has(extname(entry.name))) {
        collected.push(fullPath);
      }
    }
  }
}

function collectFiles() {
  const inputPaths = PATHS_RAW.split(/\s+/).filter(Boolean);
  const collected = [];

  for (const p of inputPaths) {
    if (collected.length >= MAX_FILES) break;
    const abs = p.startsWith('/') ? p : join(WORKSPACE, p);

    let stat;
    try { stat = statSync(abs); } catch { continue; }

    if (stat.isDirectory()) {
      walkDir(abs, collected);
    } else if (stat.isFile() && ALLOWED_EXTENSIONS.has(extname(abs))) {
      collected.push(abs);
    }
  }

  // Read content, applying per-file size cap
  const files = [];
  for (const absPath of collected) {
    let content;
    try {
      const buf = readFileSync(absPath);
      if (buf.byteLength > MAX_FILE_BYTES) {
        console.warn(`[aiharness] Skipping ${absPath}: exceeds 256 KB limit`);
        continue;
      }
      content = buf.toString('utf8');
    } catch {
      continue;
    }
    files.push({ path: relative(WORKSPACE, absPath), content });
  }

  return files;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

function buildHeaders() {
  const h = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (API_KEY) h['Authorization'] = `Bearer ${API_KEY}`;
  return h;
}

async function apiPost(path, body) {
  const url = `${API_URL}${path}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: buildHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`POST ${url} → ${res.status} ${res.statusText}: ${text}`);
  }
  return res.json();
}

async function apiGet(path) {
  const url = `${API_URL}${path}`;
  const res = await fetch(url, { headers: buildHeaders() });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`GET ${url} → ${res.status} ${res.statusText}: ${text}`);
  }
  return res.json();
}

async function apiGetRaw(path) {
  const url = `${API_URL}${path}`;
  const res = await fetch(url, {
    headers: { ...buildHeaders(), 'Accept': 'application/json' },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`GET ${url} → ${res.status} ${res.statusText}: ${text}`);
  }
  return res.text();
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

async function pollScan(scanId) {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let dots = 0;

  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));

    const data = await apiGet(`/api/scans/${scanId}`);
    const status = data?.scan?.status;

    process.stdout.write('.');
    dots++;
    if (dots % 30 === 0) process.stdout.write('\n');

    if (status === 'completed') {
      process.stdout.write('\n');
      return data;
    }
    if (status === 'failed') {
      process.stdout.write('\n');
      throw new Error(`Scan ${scanId} failed on the server.`);
    }
  }

  throw new Error(`Scan ${scanId} timed out after 5 minutes.`);
}

// ---------------------------------------------------------------------------
// Severity comparison
// ---------------------------------------------------------------------------

function severityIndex(sev) {
  const idx = SEVERITY_ORDER.indexOf((sev || 'info').toLowerCase());
  return idx === -1 ? SEVERITY_ORDER.length : idx; // unknown → lowest priority
}

function shouldFail(findings) {
  if (FAIL_SEVERITY === 'none') return false;
  const threshold = severityIndex(FAIL_SEVERITY);
  return findings.some(f => severityIndex(f.severity) <= threshold);
}

// ---------------------------------------------------------------------------
// Summary printer
// ---------------------------------------------------------------------------

function printSummary(findings) {
  if (!findings || findings.length === 0) {
    console.log('\n[aiharness] No findings. ✓');
    return;
  }

  const counts = {};
  for (const sev of SEVERITY_ORDER) counts[sev] = 0;
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase();
    counts[s] = (counts[s] || 0) + 1;
  }

  console.log(`\n[aiharness] Findings summary (${findings.length} total):`);
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    if (counts[sev]) console.log(`  ${sev.padEnd(8)}: ${counts[sev]}`);
  }
  console.log('');

  const top = findings.slice(0, 10);
  for (const f of top) {
    const loc = f.file ? `${f.file}:${f.startLine ?? '?'}` : '(unknown location)';
    console.log(`  [${(f.severity || '?').toUpperCase()}] ${f.cwe || 'CWE-?'} @ ${loc}`);
    if (f.explanation) console.log(`    ${f.explanation.slice(0, 120)}`);
  }
  if (findings.length > 10) {
    console.log(`  ... and ${findings.length - 10} more findings (see SARIF for full list)`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('[aiharness] Collecting source files…');
  const files = collectFiles();

  if (files.length === 0) {
    console.error('[aiharness] No supported source files found under the specified paths.');
    process.exit(1);
  }

  console.log(`[aiharness] Sending ${files.length} file(s) to ${API_URL} (language: ${LANGUAGE})…`);

  const body = { language: LANGUAGE, files };
  if (API_KEY) body.apiKey = API_KEY;

  let scanId;
  try {
    const created = await apiPost('/api/scans', body);
    scanId = created?.id;
    if (!scanId) throw new Error(`Unexpected response: ${JSON.stringify(created)}`);
  } catch (err) {
    console.error(`[aiharness] Failed to create scan: ${err.message}`);
    process.exit(1);
  }

  console.log(`[aiharness] Scan created — ID: ${scanId}`);
  console.log('[aiharness] Polling for results (up to 5 minutes)…');

  let result;
  try {
    result = await pollScan(scanId);
  } catch (err) {
    console.error(`[aiharness] ${err.message}`);
    process.exit(1);
  }

  const findings = result?.findings ?? [];
  printSummary(findings);

  // Fetch SARIF
  console.log('[aiharness] Fetching SARIF output…');
  let sarifContent;
  try {
    sarifContent = await apiGetRaw(`/api/scans/${scanId}/sarif`);
  } catch (err) {
    console.error(`[aiharness] Failed to fetch SARIF: ${err.message}`);
    process.exit(1);
  }

  // Write SARIF file (resolve relative to workspace)
  const sarifPath = SARIF_FILE.startsWith('/') ? SARIF_FILE : join(WORKSPACE, SARIF_FILE);
  try {
    writeFileSync(sarifPath, sarifContent, 'utf8');
    console.log(`[aiharness] SARIF written to ${sarifPath}`);
  } catch (err) {
    console.error(`[aiharness] Failed to write SARIF file: ${err.message}`);
    process.exit(1);
  }

  // Exit code
  if (shouldFail(findings)) {
    console.error(
      `[aiharness] Job failed: findings at or above severity "${FAIL_SEVERITY}" were detected.`
    );
    process.exit(1);
  }

  console.log('[aiharness] Scan complete.');
}

main().catch(err => {
  console.error(`[aiharness] Unexpected error: ${err.message}`);
  process.exit(1);
});
