# HGD Verifier

Run from the repository root or an extracted release bundle:

```bash
node verify/hgd-verify.mjs records/cmd-002
```

The verifier checks public schema shape, canonical manifest bytes, artifact hashes and byte lengths, identity, chain links, Sigstore signer identity, OIDC issuer, and transparency-backed bundle verification. It does not verify model correctness, investment suitability, future performance, private input completeness, economic interpretation, or regulatory approval.
