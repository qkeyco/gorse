# Betterleaks rule set

- Source: https://github.com/betterleaks/betterleaks (file `config/betterleaks.toml`)
- Version: v1.10.0
- Commit: 8d77e1712fb06fd14444cc648686f1d5655e28a8
- Taken: 2026-11-07
- Licence: MIT, Copyright (c) 2026 Zachary Rice (see `LICENSE` in this folder)

Betterleaks is the Gitleaks author's successor rule set: the same TOML shape,
more than twice the rules, and a `filter` expression per rule in place of
allowlists. `betterleaks.toml` is the upstream default configuration, copied
unchanged. Gorse does not bundle or run the Betterleaks program and never runs
its `validate` or `analyze` programs (those contact the provider; Gorse's
scan contacts nobody). `scripts/betterleaks-import.ts` converts the rules into
Gorse's own matcher table (`taint_engine/src/rules/betterleaks_generated.rs`),
which the taint engine runs with its own dependency-free regex subset
(`taint_engine/src/rules/minire.rs`). Each rule's filter is carried as far as a
line scan can evaluate it (entropy thresholds, regex and stopword lists);
the importer prints every condition it leaves out.

To update: the monthly `betterleaks-update` job in
`.github/workflows/upstream-review.yml` does this and opens a pull request.
By hand: replace `betterleaks.toml` with the new release's file (check
`LICENSE` is unchanged), update the Version, Commit and Taken lines above (the
importer and the licence notices read them from here), then run
`node scripts/betterleaks-import.ts`, `node scripts/third-party-notices.ts` and
`cargo test -p hedgehog_taint`.
