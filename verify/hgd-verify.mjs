#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
const EXPECTED_IDENTITY = 'https://github.com/highgravitydataporfolios-ux/hgd-integrity/.github/workflows/publish-integrity.yml@refs/heads/main';
const EXPECTED_ISSUER = 'https://token.actions.githubusercontent.com';
const PRIVATE_MARKERS = [
  '/' + 'Users' + '/',
  '/' + 'home' + '/',
  'C:' + String.fromCharCode(92) + 'Users' + String.fromCharCode(92),
  'file:' + '/' + '/',
  'reports' + '/_qa',
  'ops' + '/runs',
  'source_' + 'manifests',
  'analytical_state_' + 'certificate',
];
function fail(message) { console.error('HGD_VERIFY_FAIL: ' + message); process.exit(1); }
function assert(condition, message) { if (!condition) fail(message); }
function sha256(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
function canonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const type = typeof value;
  if (type === 'string') return JSON.stringify(value);
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new Error('nonfinite number');
    if (Object.is(value, -0)) throw new Error('negative zero');
    return JSON.stringify(value);
  }
  if (type === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
  }
  throw new Error('unsupported JSON type ' + type);
}
function hasDuplicateKeys(text) {
  let i = 0;
  function ws() { while (i < text.length && /\s/.test(text[i])) i++; }
  function str() {
    if (text[i++] !== '"') throw new Error('expected JSON string');
    let out = '';
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') return out;
      if (c === '\\') { out += c + text[i++]; } else { out += c; }
    }
    throw new Error('unterminated JSON string');
  }
  function primitive() { while (i < text.length && !/[\s,\]}]/.test(text[i])) i++; }
  function arr() {
    i++; ws(); if (text[i] === ']') { i++; return false; }
    while (i < text.length) { if (val()) return true; ws(); if (text[i] === ',') { i++; continue; } if (text[i] === ']') { i++; return false; } throw new Error('bad JSON array'); }
    throw new Error('unterminated JSON array');
  }
  function obj() {
    i++; const seen = new Set(); ws(); if (text[i] === '}') { i++; return false; }
    while (i < text.length) {
      ws(); const key = str(); if (seen.has(key)) return true; seen.add(key); ws(); if (text[i++] !== ':') throw new Error('bad JSON object');
      if (val()) return true; ws(); if (text[i] === ',') { i++; continue; } if (text[i] === '}') { i++; return false; } throw new Error('bad JSON object');
    }
    throw new Error('unterminated JSON object');
  }
  function val() { ws(); const c = text[i]; if (c === '{') return obj(); if (c === '[') return arr(); if (c === '"') { str(); return false; } primitive(); return false; }
  return val();
}
function readJsonNoDuplicates(file) {
  const text = fs.readFileSync(file, 'utf8');
  assert(!hasDuplicateKeys(text), 'duplicate JSON key: ' + file);
  return JSON.parse(text);
}
function readManifestWithDigest(bundleDir) {
  const file = path.join(bundleDir, 'hgd-integrity-manifest-v1.json');
  const bytes = fs.readFileSync(file);
  const data = readJsonNoDuplicates(file);
  return { data, digest: sha256(bytes), dir: bundleDir };
}
function ensureNoPrivateMarkers(file, buffer) {
  const text = buffer.toString('utf8');
  for (const marker of PRIVATE_MARKERS) assert(!text.includes(marker), 'private marker in ' + file);
}
const args = process.argv.slice(2);
const target = args.find((arg) => !arg.startsWith('--'));
const skipSignature = args.includes('--skip-signature');
if (!target) fail('usage: node verify/hgd-verify.mjs records/cmd-002 [--skip-signature]');
const dir = path.resolve(target);
const manifestPath = path.join(dir, 'hgd-integrity-manifest-v1.json');
const manifestBytes = fs.readFileSync(manifestPath);
const manifest = readJsonNoDuplicates(manifestPath);
assert(manifestBytes.equals(Buffer.from(canonicalize(manifest))), 'manifest is not canonical RFC 8785 bytes');
assert(manifest.schema === 'hgd.integrity.manifest.v1', 'unsupported manifest schema');
assert(manifest.series === 'HGD_CMD', 'unsupported manifest series');
assert(manifest.hash_algorithm === 'sha256', 'unsupported hash algorithm');
assert(manifest.status === 'ACTIVE', 'manifest status is not ACTIVE');
assert(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(manifest.canonical_publication_at), 'bad canonical publication timestamp');
assert(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(manifest.integrity_registration_at), 'bad integrity registration timestamp');
const receipt = readJsonNoDuplicates(path.join(dir, 'verification-receipt.json'));
assert(receipt.manifest_sha256 === sha256(manifestBytes), 'manifest digest mismatch');
const seenFiles = new Set();
for (const artifact of manifest.artifacts) {
  assert(!seenFiles.has(artifact.filename), 'duplicate artifact filename');
  seenFiles.add(artifact.filename);
  const artifactPath = path.join(dir, artifact.filename);
  const bytes = fs.readFileSync(artifactPath);
  assert(sha256(bytes) === artifact.sha256, 'artifact hash mismatch: ' + artifact.filename);
  assert(bytes.length === artifact.byte_length, 'artifact byte length mismatch: ' + artifact.filename);
  ensureNoPrivateMarkers(artifact.filename, bytes);
}
const allowedBundleFiles = new Set([
  ...seenFiles,
  'hgd-integrity-manifest-v1.json',
  'hgd-integrity-manifest-v1.sigstore.json',
  'SHA256SUMS',
  'verification-receipt.json',
  'README.md',
]);
for (const entry of fs.readdirSync(dir)) {
  assert(allowedBundleFiles.has(entry), 'unregistered file in release directory: ' + entry);
}
const record = readJsonNoDuplicates(path.join(dir, 'record.json'));
const brief = readJsonNoDuplicates(path.join(dir, 'brief.json'));
assert(record.citation_id === manifest.citation_id, 'record citation mismatch');
assert(record.machine_identity === manifest.publication_id, 'record machine identity mismatch');
assert(record.canonical_product_id === manifest.canonical_product_id, 'canonical product mismatch');
assert(brief.associated_cmd && brief.associated_cmd.citation_id === manifest.citation_id, 'brief association mismatch');
assert(Array.isArray(brief.sections) && brief.sections.length === 3, 'Brief v2 must have exactly three sections');
assert(brief.visual_contract && brief.visual_contract.chart_count === 0 && brief.visual_contract.figure_count === 0, 'Brief v2 visual contract failed');
if (manifest.chain_position === 0) {
  assert(manifest.genesis === true, 'genesis manifest must have genesis=true');
  assert(manifest.previous_manifest_sha256 === null, 'genesis predecessor must be null');
} else {
  assert(manifest.genesis === false, 'non-genesis manifest must have genesis=false');
  assert(/^[a-f0-9]{64}$/.test(manifest.previous_manifest_sha256 || ''), 'missing predecessor digest');
}
const siblingDirs = fs.readdirSync(path.dirname(dir))
  .map((entry) => path.join(path.dirname(dir), entry))
  .filter((entry) => fs.existsSync(path.join(entry, 'hgd-integrity-manifest-v1.json')));
if (siblingDirs.length > 1) {
  const siblings = siblingDirs.map(readManifestWithDigest).sort((a, b) => a.data.chain_position - b.data.chain_position);
  const citationIds = new Set();
  const publicationIds = new Set();
  const positions = new Set();
  for (const item of siblings) {
    assert(!citationIds.has(item.data.citation_id), 'duplicate CMD citation identity in local chain');
    assert(!publicationIds.has(item.data.publication_id), 'duplicate CMD publication identity in local chain');
    assert(!positions.has(item.data.chain_position), 'duplicate chain position in local chain');
    citationIds.add(item.data.citation_id);
    publicationIds.add(item.data.publication_id);
    positions.add(item.data.chain_position);
  }
  assert(siblings[0].data.genesis === true && siblings[0].data.previous_manifest_sha256 === null, 'local chain genesis is invalid');
  for (let i = 1; i < siblings.length; i++) {
    assert(siblings[i].data.genesis === false, 'non-genesis local chain entry has genesis=true');
    assert(siblings[i].data.previous_manifest_sha256 === siblings[i - 1].digest, 'local chain predecessor digest mismatch');
  }
}
if (!skipSignature) {
  const bundle = path.join(dir, 'hgd-integrity-manifest-v1.sigstore.json');
  assert(fs.existsSync(bundle), 'missing Sigstore bundle');
  execFileSync('cosign', ['verify-blob', manifestPath, '--bundle', bundle, '--certificate-identity', EXPECTED_IDENTITY, '--certificate-oidc-issuer', EXPECTED_ISSUER], {stdio: 'pipe'});
}
console.log(JSON.stringify({result: 'PASS', citation_id: manifest.citation_id, manifest_sha256: sha256(manifestBytes), signature_verified: !skipSignature}, null, 2));
