# Blocked

Work that was started but cannot be finished here, with what it is waiting on.

## `tatar-kuber update` — the scanner pins are not filled in

**What works.** `internal/update` implements the specification's sequence
(Doc #5 §5) end to end: download → verify SHA256 → verify signature (stubbed) →
install → write `tools.lock.yaml`. A checksum mismatch installs nothing, an
unpinned scanner is refused before the request is made, `--dry-run` and
`--check` touch neither the network nor the disk, and the tests cover all of it
against a `net/http/httptest` server.

**What is blocked.** The command cannot install anything until someone pins the
checksums, and nobody should pin them but a human:

1. **No expected SHA256 is shipped.** `internal/update/catalog.go` carries the
   release URL shapes only; the expected checksum comes from
   `~/.tatar-kuber/tools.lock.yaml`, and with nothing there `update` refuses
   (this is the intended fail-closed behaviour, not a missing feature). A
   checksum is a supply-chain assertion — it has to be produced by someone who
   compared it against what the upstream project published, so it cannot be
   generated here and committed as if it had been checked.

   Two of the four projects make this harder than it should be: trivy and
   popeye publish a checksum file next to the release
   (`trivy_<v>_checksums.txt`, `checksums.sha256`), **kubescape and checkov
   publish none** at the releases checked (kubescape v3.0.8, checkov 3.2.0), so
   their checksums can only be obtained by downloading the artefact and hashing
   it — which is exactly the trust-on-first-use step this command exists to
   avoid. A decision is needed on where those two checksums may legitimately
   come from.

2. **The pinned versions are stale.** The catalogue defaults are the versions
   the specification itself names (Doc #5 §6): trivy 0.53.0, kubescape 3.0.8,
   checkov 3.2.0, popeye 0.21.5. Trivy's v0.53.0 release assets no longer
   resolve on GitHub (the tag page is served, the asset is a 404; trivy's latest
   release is v0.74.0 as of 2026-09-30), so that default URL is already dead. A
   stale default can only ever produce a refusal, never a bad binary, but the
   pins want a maintainer's refresh before the command is useful.

3. **cosign verification is a stub.** `update.NoSignatureVerifier` checks
   nothing and answers `false`, and every surface says so: the console prints a
   warning on each run and `tools.lock.yaml` records `cosign: "unverified"`.
   The `SignatureVerifier` interface is the seam a real implementation drops
   into — `Apply`, the lock file and the CLI already handle both answers — but
   choosing the trust root (sigstore keyless against each project's published
   identity, or a pinned public key per scanner) is a product decision.

**Also outstanding:** `docs/05_CLI-Specification.docx` §5 and its version notes
still describe `update` as "v2-т ТӨЛӨВЛӨСӨН, v1-д хэрэгжээгүй". That text lives
in the Word document, which is the only direction the converter runs in
(`scripts/docx-to-md.py` renders .docx → .md, never the reverse), so it has to
be corrected in Word and the Markdown regenerated from it.
