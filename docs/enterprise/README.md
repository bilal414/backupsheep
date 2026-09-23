# BackupSheep enterprise recovery manual

This folder contains the visual enterprise documentation for BackupSheep. It is a
dependency-free static site that works from a local file, a basic static server, or a
documentation host. The manual is intentionally organized around recoverability and
operational evidence rather than implementation modules.

## Preview

From the repository root:

```bash
python3 -m http.server 8042
```

Then open `http://127.0.0.1:8042/docs/enterprise/`.

## Source-derived references

The searchable API explorer is generated from `bruno/route-manifest.json`, which is in
turn generated from Django's URL resolver. The configuration explorer is generated from
the public `.env_sample` plus variable reads in `backupsheep/settings.py`; it never reads
`.env` or runtime secrets. Settings-only test and support knobs are labeled separately.
The catalog also records the source revision, committed manifest count, and whether
uncommitted API/Bruno changes were included so a working-tree route cannot silently look
like a released contract.

Refresh both catalogs after API or configuration changes:

```bash
python3 docs/enterprise/tools/build_catalogs.py
python3 docs/enterprise/tools/validate_docs.py
```

For a documentation-only commit while unrelated API work is present in the working
tree, generate the public catalog from the committed API instead:

```bash
python3 docs/enterprise/tools/build_catalogs.py --git-ref HEAD
python3 docs/enterprise/tools/validate_docs.py
```

The resulting provenance badge says that uncommitted API changes were intentionally
excluded. This keeps a documentation commit reproducible without staging another
workstream's routes, tests, or Bruno requests.

Regenerate the Bruno resolver manifest first when URL routing changes:

```bash
.venv/bin/python bruno/scripts/generate_collection.py
.venv/bin/python bruno/scripts/validate_collection.py
python3 docs/enterprise/tools/build_catalogs.py
```

Review the generated manifest and catalog diff before committing. Do not run the full
Bruno collection against production: many requests mutate BackupSheep or provider state.

## Canonical inputs

- Product and workflow content: `docs/features/`, `docs/guides/`, `docs/reference/`
- API routes: `bruno/route-manifest.json`
- API examples: `bruno/requests/`
- Configuration: `.env_sample` and `backupsheep/settings.py`
- Security posture: `SECURITY.md`
- Implementation evidence: source and tests linked from each manual page

Dated E2E reports remain evidence for the exact runs they describe. They are not silently
promoted into universal provider guarantees in this manual.
