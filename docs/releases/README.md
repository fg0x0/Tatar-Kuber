# Release notes

The source of truth for every release's notes. GitHub's release page is a *copy*.

This exists because the copy is mutable and has been overwritten twice. GoReleaser
runs with `mode: replace`, so any run that resolves to an existing release rewrites
its body with an auto-generated changelog — on 2026-09-27 that silently reduced
v1.0.3's notes from 6849 characters to 1024, and nothing turned red.

With the text kept here, restoring is one command:

```bash
gh release edit vX.Y.Z --notes-file docs/releases/vX.Y.Z.md
```

`.github/workflows/release-notes.yml` compares every file here against what is
published and fails if they have drifted, so an overwrite is noticed the next day
rather than by a reader months later.

Write the notes here **before** tagging, then point `gh release edit` at the file.
Never paste release notes straight into the GitHub UI — that copy has no history,
no review, and no backup.
