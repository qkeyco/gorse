# cl100k_base vocabulary (tiktoken)

`cl100k_base.bin` is OpenAI's cl100k_base byte-pair vocabulary, the rank file
tiktoken loads, packed into the compact form the detection engine embeds
(`taint_engine/src/rules/tokens.rs`): one length-prefixed byte string per
rank, rank 0 first. Gorse uses it for one thing: the Betterleaks `tokenRatio`
filter, which drops a candidate secret that splits into few, long word
pieces, because such text reads like prose or code rather than a key.

- Source: https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken
- Source SHA-256: 223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7
- Packed SHA-256: 6bfd43f7b31b50b645b3228413547e662af1ae4801e9b192b9791680a71d650c
- Ranks: 100256
- Taken: 2026-11-07
- Licence: MIT (tiktoken, Copyright (c) 2022 OpenAI, Shantanu Jain), reproduced in `LICENSE`

The source hash is the one tiktoken itself verifies, so the packer refuses
any other file. Regenerate with `node scripts/cl100k-pack.ts` (fetches the
source) or `node scripts/cl100k-pack.ts path/to/cl100k_base.tiktoken`. The
vocabulary is fixed; it never needs updating.

Only the data is third-party. The splitting and merging code in
`tokens.rs` is Gorse's own, written from the published pre-tokenizer
pattern and the byte-pair merge rule, and checked against tiktoken's counts
in its tests.
