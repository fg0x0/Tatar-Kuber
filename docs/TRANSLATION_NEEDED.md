# Translation needed — Mongolian

A worklist, not a translation. **Nothing here has been machine-translated**, and
nothing should be: the Mongolian in this repo is written, and a transliterated
stand-in would be worse than an honest gap.

Generated 2026-09-30 by classifying every tracked `.md` as entirely English,
bilingual (carrying a `Монгол хэл дээр` half), or mixed, plus the CLI message
catalogue's own `awaitingMN` list.

**Priority is about who reads it**, not length. This repo's users are platform
and security engineers running a CI gate, so English is less of a barrier here
than in Tatar-Shield — but the CLI is the exception: it says it speaks Mongolian
with `--lang mn`, and where it silently does not, it is breaking its own promise.

---

## High — the CLI claims to speak Mongolian and does not, here

`internal/cli/messages.go` carries an `awaitingMN` list: catalogue IDs with
English text and no Mongolian yet. They fall back to English at runtime rather
than printing blank, and `TestCatalogHasEveryLanguage` fails if an ID is dropped
from the list without gaining a Mongolian string — so this list cannot rot
silently. **21 IDs**, all short (a line or a column heading each):

| IDs | What the user sees |
|---|---|
| `update.check.absent` `update.check.changes` `update.check.header` `update.check.uptodate` `update.col.pinned` `update.installed` `update.installed.header` `update.dryrun.header` `update.plan.unpinned` `update.cosign.stub` | everything `tatar-kuber update --check` and `--dry-run` print |
| `flag.update.check` `flag.update.dryrun` `flag.update.home` `flag.update.scanner` | the four `update` flag descriptions in `--help` |
| `err.update.scanner.unknown` | the error for an unknown scanner name |
| `verify.controls` `verify.count` `verify.findings` `verify.min` `verify.missing.header` `verify.total` | the `verify-lab` diagnostic table — **these were English-only before this work too**, not introduced by it |

Roughly **250 words** in total. Removing an ID from `awaitingMN` and adding its
`mn` string is the whole change.

## Low — contributor-facing

| Section | File | Words | Note |
|---|---|---:|---|
| The engineering documents (.docx and .md) | `CONTRIBUTING.md` | ~200 | New section; the Mongolian half of CONTRIBUTING.md is a short summary rather than a mirror, so this needs a Mongolian summary, not a translation. |
| Updating the scanners | `README.md` (English half) | ~120 | The `update` paragraph — the checksum refusal, `--dry-run`/`--check`, cosign not implemented. The Mongolian half has no counterpart yet. |
| *(whole file)* | `CODE_OF_CONDUCT.md` | 313 | **Do not hand-translate.** Contributor Covenant v2.1 has an official Mongolian translation — use it rather than writing a second, divergent wording. |
| *(whole file)* | `docs/releases/README.md` | 152 | Index of the release notes. |
| *(whole file)* | `.github/ISSUE_TEMPLATE/*.md`, `PULL_REQUEST_TEMPLATE.md` | 221 | Contributor-facing. |
| *(whole file)* | `BLOCKED.md` | 472 | A working note about what `update` is waiting on; it will be deleted once the pins are filled in. |
| *(whole package)* | `internal/update/*.go` comments | — | The new package's comments are English, unlike the Mongolian comments elsewhere in the repo. Worth a pass for consistency, but it is code commentary, not user-facing text. |

---

## Deliberately *not* a gap

- **`README.md`** carries a full Mongolian half, enforced structurally by
  `internal/canonical/readme_test.go` in CI.
- **The six engineering specs** (`docs/0*.md`) are Mongolian-first already, and
  are generated from the `.docx` — never edit the `.md` to change wording, see
  CONTRIBUTING.md.
- **`ROADMAP.md`, `docs/MITRE_ATTACK.md`, `docs/coverage.md`, the release
  notes** are already Mongolian or mixed.

## If you translate one thing

The 21 `awaitingMN` IDs. They are the only place where the tool *claims* to
speak Mongolian and then does not, and each one is a single line.
