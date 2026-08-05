#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
const EXPECTED_IDENTITY = 'https://github.com/highgravitydataporfolios-ux/hgd-integrity/.github/workflows/publish-integrity.yml@refs/heads/main';
const EXPECTED_ISSUER = 'https://token.actions.githubusercontent.com';
const PRIVATE_MARKERS = ['/'+'Users'+'/', '/'+'home'+'/', 'C:'+String.fromCharCode(92)+'Users'+String.fromCharCode(92), 'file:'+'/'+'/', 'reports'+'/_qa', 'ops'+'/runs', 'source_'+'manifests', 'analytical_state_'+'certificate'];
function fail(message){ console.error('HGD_VERIFY_FAIL: '+message); process.exit(1); }
function assert(condition,message){ if(!condition) fail(message); }
function sha256(buffer){ return crypto.createHash('sha256').update(buffer).digest('hex'); }
function hasDuplicateKeys(text){ let i=0; function ws(){ while(i<text.length&&/\s/.test(text[i])) i++; } function str(){ if(text[i++]!=='"') throw new Error('expected JSON string'); while(i<text.length){ const c=text[i++]; if(c==='"') return; if(c==='\\') i++; } throw new Error('unterminated JSON string'); } function primitive(){ while(i<text.length&&!/[\s,\]}]/.test(text[i])) i++; } function arr(){ i++; ws(); if(text[i]===']'){i++; return false;} while(i<text.length){ if(val()) return true; ws(); if(text[i]===','){i++; continue;} if(text[i]===']'){i++; return false;} throw new Error('bad JSON array'); } throw new Error('unterminated JSON array'); } function obj(){ i++; const seen=new Set(); ws(); if(text[i]==='}'){i++; return false;} while(i<text.length){ ws(); const start=i; str(); const key=JSON.parse(text.slice(start,i)); if(seen.has(key)) return true; seen.add(key); ws(); if(text[i++]!==':') throw new Error('bad JSON object'); if(val()) return true; ws(); if(text[i]===','){i++; continue;} if(text[i]==='}'){i++; return false;} throw new Error('bad JSON object'); } throw new Error('unterminated JSON object'); } function val(){ ws(); const c=text[i]; if(c==='{') return obj(); if(c==='[') return arr(); if(c==='"'){str(); return false;} primitive(); return false; } return val(); }
function readJsonNoDuplicates(file){ const text=fs.readFileSync(file,'utf8'); assert(!hasDuplicateKeys(text),'duplicate JSON key: '+file); return JSON.parse(text); }
function ensureNoPrivateMarkers(file,buffer){ const text=buffer.toString('utf8'); for(const marker of PRIVATE_MARKERS) assert(!text.includes(marker),'private marker in '+file); }
const args=process.argv.slice(2); const target=args.find((arg)=>!arg.startsWith('--')); const skipSignature=args.includes('--skip-signature'); if(!target) fail('usage: node verify/hgd-verify.mjs records/cmd-002-v2 [--skip-signature]');
const dir=path.resolve(target); const v2Path=path.join(dir,'hgd-integrity-manifest-v2.json'); const v1Path=path.join(dir,'hgd-integrity-manifest-v1.json'); const manifestPath=fs.existsSync(v2Path)?v2Path:v1Path; const manifestFile=path.basename(manifestPath); const manifestBytes=fs.readFileSync(manifestPath); const manifest=readJsonNoDuplicates(manifestPath); const manifestDigest=sha256(manifestBytes);
if(manifest.schema==='hgd.integrity.manifest.v2'){
  assert(manifest.status==='ACTIVE','manifest status is not ACTIVE');
  assert(manifest.publication_id==='hgd:cmd:002','publication id mismatch');
  assert(manifest.active_record_revision===2,'active Record revision mismatch');
  assert([3,4].includes(manifest.active_brief_revision),'active Brief revision mismatch');
  assert(/^[a-f0-9]{64}$/.test(manifest.series_predecessor_manifest_sha256),'missing series predecessor digest');
  assert(/^[a-f0-9]{64}$/.test(manifest.supersedes_manifest_sha256),'missing superseded revision digest');
  const receipt=readJsonNoDuplicates(path.join(dir,'verification-receipt.json'));
  assert(receipt.manifest_sha256===manifestDigest,'manifest digest mismatch');
  const seen=new Set();
  for(const artifact of manifest.artifacts){ assert(!seen.has(artifact.filename),'duplicate artifact filename'); seen.add(artifact.filename); const file=path.join(dir,artifact.filename); const bytes=fs.readFileSync(file); assert(sha256(bytes)===artifact.sha256,'artifact hash mismatch: '+artifact.filename); assert(bytes.length===artifact.byte_length,'artifact byte length mismatch: '+artifact.filename); ensureNoPrivateMarkers(artifact.filename,bytes); }
  const allowed=new Set([...seen, manifestFile, 'hgd-integrity-manifest-v2.sigstore.json', 'SHA256SUMS', 'verification-receipt.json', 'supersession-receipt.json', 'README.md']);
  for(const entry of fs.readdirSync(dir)) assert(allowed.has(entry),'unregistered file in release directory: '+entry);
  if(!skipSignature){ const bundle=path.join(dir,'hgd-integrity-manifest-v2.sigstore.json'); assert(fs.existsSync(bundle),'missing Sigstore bundle'); execFileSync('cosign',['verify-blob',manifestPath,'--bundle',bundle,'--certificate-identity',EXPECTED_IDENTITY,'--certificate-oidc-issuer',EXPECTED_ISSUER],{stdio:'pipe'}); }
  console.log(JSON.stringify({result:'PASS', citation_id:manifest.citation_id, manifest_sha256:manifestDigest, schema:manifest.schema, signature_verified:!skipSignature},null,2));
  process.exit(0);
}
assert(manifest.schema==='hgd.integrity.manifest.v1','unsupported manifest schema');
assert(manifest.status==='ACTIVE','manifest status is not ACTIVE');
const receipt=readJsonNoDuplicates(path.join(dir,'verification-receipt.json')); assert(receipt.manifest_sha256===manifestDigest,'manifest digest mismatch');
const seenFiles=new Set(); for(const artifact of manifest.artifacts){ assert(!seenFiles.has(artifact.filename),'duplicate artifact filename'); seenFiles.add(artifact.filename); const artifactPath=path.join(dir,artifact.filename); const bytes=fs.readFileSync(artifactPath); assert(sha256(bytes)===artifact.sha256,'artifact hash mismatch: '+artifact.filename); assert(bytes.length===artifact.byte_length,'artifact byte length mismatch: '+artifact.filename); ensureNoPrivateMarkers(artifact.filename,bytes); }
const allowedBundleFiles=new Set([...seenFiles,'hgd-integrity-manifest-v1.json','hgd-integrity-manifest-v1.sigstore.json','SHA256SUMS','verification-receipt.json','README.md']); for(const entry of fs.readdirSync(dir)) assert(allowedBundleFiles.has(entry),'unregistered file in release directory: '+entry);
if(!skipSignature){ const bundle=path.join(dir,'hgd-integrity-manifest-v1.sigstore.json'); assert(fs.existsSync(bundle),'missing Sigstore bundle'); execFileSync('cosign',['verify-blob',manifestPath,'--bundle',bundle,'--certificate-identity',EXPECTED_IDENTITY,'--certificate-oidc-issuer',EXPECTED_ISSUER],{stdio:'pipe'}); }
console.log(JSON.stringify({result:'PASS', citation_id:manifest.citation_id, manifest_sha256:manifestDigest, schema:manifest.schema, signature_verified:!skipSignature},null,2));
