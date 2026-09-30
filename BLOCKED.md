# Blocked

Work that was started but cannot be finished here, with what it is waiting on.

## `tatar-kuber update` — three of four scanners are pinned

**Resolved 2026-09-30.** The command installs. `tools.lock.yaml` at the repo
root ships pins for trivy, kubescape and popeye, each obtained the only way a
pin is worth anything:

1. the latest stable release was read from the project's GitHub releases API
2. the linux/amd64 artefact was downloaded
3. its SHA256 was computed locally
4. that value was compared against the checksum file the project itself
   publishes on the same release

All three matched. Step 4 is the one that counts — a checksum computed from a
download you already have proves only that the file did not change in transit.

Verified end to end against the live release: `tatar-kuber update --scanner
popeye` downloaded 21 MB from GitHub, the SHA256 matched the pin, the binary
installed and runs, and `tools.lock.yaml` recorded `installed: "0.22.1"`
separately from the pin.

The catalogue's URL shapes were stale and were refreshed at the same time:
kubescape v4 renamed **every** asset (the v3 `kubescape-ubuntu-latest` names do
not exist on any v4 release) and checkov moved the version out of its filenames.
Both would have 404'd.

### Still blocked: checkov has nothing to verify against

`bridgecrewio/checkov` publishes **no checksum file, no signature and no build
attestation** for its GitHub release archives. Release 3.3.20 ships four `.zip`
assets and nothing else; the release notes carry no digest; GitHub's
attestations endpoint returns 404 for the artefact.

So checkov is deliberately left unpinned and `update` refuses to install it —
the designed-for fail-closed state, not an oversight. Recording the SHA256 of a
zip downloaded here would say "this is what arrived on one machine on one day"
in the same shape as three pins that mean considerably more.

`internal/update/defaultlock_test.go` asserts the set of unpinned scanners is
exactly `{checkov}`, in both directions: dropping a pin fails, and **pinning
checkov also fails**, because that pin needs a human to record where the
checksum came from.

Ways out, for whoever picks this up:

* install checkov from PyPI, where every file has a recorded hash and
  `pip install --require-hashes` can enforce it. It is a wheel rather than a
  self-contained binary, so the adapter would need to know that.
* ask bridgecrewio to publish checksums for the release archives.
* accept trust-on-first-use for this one scanner, deliberately, and say so in
  `tools.lock.yaml`.

### Still blocked: cosign verification is a stub

`update.NoSignatureVerifier` checks nothing and answers `false`, and every
surface says so — the console prints a warning on each run and
`tools.lock.yaml` records `cosign: "unverified"`. The `SignatureVerifier`
interface is the seam a real implementation drops into; `Apply`, the lock file
and the CLI already handle both answers.

What is missing is a decision, not code: the trust root. Either sigstore
keyless verification against each project's published workflow identity, or a
pinned public key per scanner. Note kubescape already ships
`checksums.sha256.sig` and `checksums.sha256.pem` next to its release, so it is
the one that could be verified first.

### Pins are per-platform

The shipped pins are for **linux/amd64**. `update` on another platform resolves
a different asset, whose checksum is not in the file, and refuses until someone
pins it the same way.

## Global `--lang` before the command still prints English

**Found 2026-09-30 while verifying the newly written Mongolian CLI strings.**
Not introduced by that work, and not fixed by it.

`tatar-kuber --lang mn update --check` prints **English**. `tatar-kuber update
--check --lang mn` prints Mongolian. The same split applies to every command,
including ones whose Mongolian shipped in v1.0.3:

```
$ tatar-kuber --lang mn doctor     # English headings
$ tatar-kuber doctor --lang mn     # СУУСАН / ХУВИЛБАР / ГОРИМ
```

The cause is a double read of the flag. `Execute` calls `setLang(os.Args[1:])`,
which sets `uiLang = "mn"`, then `stripLeadingLang` removes the `--lang mn` pair
so the switch does not mistake it for a command name. The command function then
calls `setLang(args)` again — every one of them does, so that `report --lang de`
is a usage error wherever it is written — and that second call **resets
`uiLang` to the default first**, finds no `--lang` in the args it was handed
(it was just stripped), and leaves the output in English.

This is not a translation gap: the strings exist in both languages, and the
`--help` text advertises `--lang` as a global flag accepted by every command,
which is the promise being broken.

Left alone here deliberately. The fix is small — carry the language `Execute`
already resolved, rather than re-deriving it per command — but it changes when
`uiLang` is set and how `explicit` is computed, and `explicit` is what `report`
uses to decide whether to re-render the document or keep the language chosen at
scan time. That is behaviour under `TestSetLangPrecedence`, `TestREADMEFlagParity`
and the golden corpus, so it belongs in its own commit with its own test for the
global position, not folded into a translation change.

`internal/cli/lang_position_test.go` already covers the *dispatch* half of this
(`--lang mn version` exits 0 rather than "unknown command"). What it does not
cover is the *output* half — that `--lang mn <cmd>` and `<cmd> --lang mn` print
the same language. A test asserting exactly that is the right first step.
