# SearchGuard VM reversing tools

This directory contains the standalone tools used for Part 2 of the Google
SearchGuard investigation. They start with one saved challenge response,
separate the JavaScript interpreter from its encrypted program, make the
interpreter readable, observe the executed path, build a capture-specific VM
profile, and recover the plaintext record written before `SG_SS` encryption.

> The complete derivation, diagrams, failed hypotheses, and interpretation of
> the results are available in the paid-subscriber article:
> **[Google SearchGuard: Reversing the Challenge VM from Scratch][article]**.

The tools remain usable without access to the article. This README explains
what every published file does and how the files fit together.

## Requirements

- Node.js 20.19+, 22.13+, or 24+
- a raw SearchGuard interstitial saved locally
- no connection to Google while running the analysis

Install the pinned dependencies:

```sh
npm ci
```

Place the saved response at:

```text
captures/response.html
```

Captured Google code is intentionally excluded from this bundle. Generated
profiles, traces, readable source, disassembly, and recovered records also stay
local.

## Recommended workflow

Run the tools in this order:

```sh
npm run build-id
npm run readable
npm run equivalence
npm run pristine
npm run cipher
npm run profile
node opcode-trace.cjs \
  --html=response.html \
  --readable=vm-readable.js \
  --pcs --coverage --output-key
npm run disasm                 # pure-static control
node static-disasm.cjs \
  --html=response.html \
  --profile=profile.json \
  --trace=pc-trace-f6ad334abefc-response.json \
  --dark
npm run recover
```

Each stage either produces an artifact consumed by a later stage or checks a
specific claim. `pristine-tap.cjs` and `record-recover.cjs` run their own
untapped controls and must report byte equality. `opcode-trace.cjs` prints the
instrumented token SHA, which must be compared with a control produced under the
same frozen inputs before the trace is trusted.

```text
captures/response.html
        |
        +-- build-compare.cjs
        |
        +-- vm-deobfuscate.cjs --> lifted-source/vm-readable.js
        |                               |
        |                               +-- run-readable-vm.cjs
        |
        +-- pristine-tap.cjs
        +-- cipher-params.cjs
        |
        +-- build-profile.cjs
        |       +-- dump-handlers.cjs
        |       +-- opcode-table.cjs
        |       +-- opcode-roles.cjs
        |       +-- cipher-params.cjs
        |
        +-- opcode-trace.cjs --> records/pc-trace-*.json
        |                               |
        +-------------------------------+-- static-disasm.cjs
        |
        +-- record-recover.cjs --> 635-byte plaintext record
```

## Files

### Input parsing and build identification

| File | Purpose |
| --- | --- |
| `lib/challenge.js` | Parses both minified and formatted challenge pages. It extracts the interpreter, encrypted `p` field, loader constants, response mode, and the build-dependent VM global name. All tools use this parser instead of relying on comments or line breaks in the HTML. |
| `lib/builds.js` | Contains reviewed bootstrap facts for interpreter builds that have already been analysed: store primitives, register file, program-counter slot, instruction-start slot, first alphabet opcode, re-key opcode, and output-key location. Profile-dependent tools reject an unknown build instead of borrowing constants from another one. |
| `build-compare.cjs` | Identifies the supplied response. It prints the interpreter length and SHA, the size of `p`, and loader values such as `ce`, `challenge_version`, `ss_cgi`, and `r`. Run this first to determine whether the remaining build-specific facts apply. |

### Readable interpreter and integrity controls

| File | Purpose |
| --- | --- |
| `vm-deobfuscate.cjs` | Parses the interpreter as an AST, simplifies only supported mixed Boolean-arithmetic expressions, checks every proposed rewrite on sampled 32-bit inputs, and formats the result. With `--no-rename`, it preserves the short identifiers required by bytecode `eval` lookups and writes the readable source under `lifted-source/`. |
| `run-readable-vm.cjs` | Executes three controlled cases: the original interpreter, the readable interpreter with original function text supplied to the fingerprint path, and an uncompensated negative control. It compares complete tokens and reports whether the readable execution is byte-identical on the observed path. |
| `pristine-tap.cjs` | Observes `String.prototype.replace` calls borrowed from the hidden iframe realm while runtime opcode bodies are created. It records only handler-shaped results and accepts them only when the tapped and untapped tokens are byte-identical. |

### Cipher and opcode profile

| File | Purpose |
| --- | --- |
| `cipher-params.cjs` | Finds the program-image ARX block function by dataflow shape, resolves its call-site parameters, and verifies them against the predictable first plaintext opcode. It reports the build's round count, round constant, and rotation. |
| `dump-handlers.cjs` | Captures runtime-installed functions written into the VM dispatch table and filters them with the same handler tag used by the dispatcher. Its standalone output is the dynamically installed subset; `build-profile.cjs` adds the base functions observed at dispatch when assembling the full profile. |
| `opcode-table.cjs` | Parses captured handler bodies and derives their operand layouts from calls to the VM's operand readers. It establishes how many variable-width operands and raw bytes each instruction consumes. |
| `opcode-roles.cjs` | Classifies the source-visible roles required for traversal, including control-flow, alphabet, string, and re-key families. It reports groups when source evidence supports a family but does not invent semantic names for every opcode. |
| `build-profile.cjs` | Orchestrates runtime handler capture, dispatcher-observed base handlers, operand-layout derivation, role classification, cipher extraction, and reviewed build facts. It writes the capture-specific JSON profile consumed by the disassembler. |

### Runtime path and output boundary

| File | Purpose |
| --- | --- |
| `opcode-trace.cjs` | Instruments the dispatcher and records executed instruction starts, live cipher state, queue bursts, and queued-handler dispatches. With `--output-key`, it also observes the separate key used by the `SG_SS` record writer. It prints the resulting token SHA for comparison with a separately generated control; unlike the two tap tools above, it does not launch its own untapped run. |
| `record-recover.cjs` | Hooks the output writer at a verified invisible point and recovers plaintext bytes before record encryption. It finds the eight-byte keystream sibling by shape rather than by an obfuscated property name and compares the tapped run with an untapped control. |

### Disassembly

| File | Purpose |
| --- | --- |
| `static-disasm.cjs` | Decodes the encrypted program image without executing it. It can perform a purely static walk or use a verified trace to decode the executed path and test observed cipher states against untouched regions. It requires a profile for the exact capture. |
| `sgss-token.js` | Supplies the small configurable ARX keystream helper used by `static-disasm.cjs`. It is not a general `SG_SS` generator; the generated profile replaces its default cipher parameters for the supplied build. |

### Package and workspace files

| File or directory | Purpose |
| --- | --- |
| `package.json` | Declares the supported Node versions, dependencies, and convenience commands shown above. |
| `package-lock.json` | Pins the dependency graph used by `npm ci`. |
| `.gitignore` | Keeps captures and every artifact derived from Google code out of commits and npm packages. |
| `captures/.gitkeep` | Preserves the local input directory in Git. Add `captures/response.html` yourself; the response is ignored. |
| `lifted-source/.gitkeep` | Preserves the directory used for generated readable interpreters and deobfuscation reports. Other contents are ignored. |
| `records/.gitkeep` | Preserves the directory used for generated handler maps, profiles, traces, and recovered records. Other contents are ignored. |
| `README.md` | Full command-oriented reference for the bundle. |
| `README_alt.md` | Public overview of the distributed files and their relationship to the subscriber article. |

## Verified reference result

The publication bundle was checked against the clean response captured on
15 September 2026:

| Measurement | Result |
| --- | --- |
| interpreter | 62,751 characters, build `f6ad334abefc` |
| encrypted `p` field | 16,831 characters |
| readable interpreter | 39 checked MBA rewrites, 4,258 formatted lines |
| readable execution | byte-identical to the original with fingerprint compensation |
| clean-realm handler transformations | 9, with an invisible tap |
| program-image cipher | 15 rounds, constant 1819, rotation 3; oracle matched |
| generated profile | 98 handlers, 93 operand layouts |
| dispatcher trace | 2,000 calls: 1,780 outer fetches and 220 queued dispatches |
| trace-guided decode | 1,220 instruction starts, 52.1% of image bits, 127 emit operations |
| plaintext output record | 635 bytes, recovered with an invisible tap |

These numbers identify the verified capture. They are not protocol constants.
A different response may contain a different interpreter, program image,
runtime opcode assignment, key, or optional fields.

## Scope

This bundle establishes the interpreter/program split, the encrypted bitstream,
the capture-specific dispatch profile, the two dispatcher input paths, the
dynamic opcode bootstrap, the macro queue layer, the observed control-flow
families, and the boundary at which the VM writes the plaintext record.

It does not provide a complete ISA, enumerate every possible branch, implement
an interpreter independent of the page VM, or generate a new accepted `SG_SS`
token from a semantic specification. The [subscriber article][article] explains
how the evidence supports those conclusions and where the remaining unknowns
begin.

The bundle can regenerate a profile for the reviewed builds in `lib/builds.js`.
Bootstrapping an unknown interpreter SHA still requires the full research tree's
primitive-discovery tools and a manual review before a new entry is added.

The tooling is MIT licensed. That license does not apply to captured Google
code or to artifacts derived from a supplied response.

<!-- Keep this slug when publishing Part 2, or update this single reference. -->
[article]: https://igorkozlowski.substack.com/p/google-searchguard-reversing-the
