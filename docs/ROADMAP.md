# PEBuilder Roadmap

Estimates assume one developer at 8–12 focused hours per week. Support claims should be tied to explicit, repeatable tests.

## M0 — Reproducible baseline (1–2 weeks)
- [ ] Document Python version and packaging metadata.
- [ ] Add clean-environment install and CLI smoke tests.
- [ ] Inventory implemented PE directories and architecture-specific paths.
- [ ] Establish a small redistributable fixture corpus.
**Exit:** clean install and deterministic test command.

## M1 — Parser correctness (3–5 weeks)
- [ ] Validate DOS/NT headers, optional-header variants and section tables.
- [ ] Test alignment, overlapping ranges, truncation and integer overflow.
- [ ] Distinguish PE32 and PE32+ explicitly.
**Exit:** malformed inputs fail safely; valid fixtures produce stable metadata.

## M2 — Lossless representation (4–8 weeks)
- [ ] Define a canonical representation for headers, sections, directories and overlays.
- [ ] Preserve unknown bytes and unsupported directory data.
- [ ] Document raw-file offsets versus RVAs and VAs.
**Exit:** supported synthetic fixtures round-trip byte-identically.

## M3 — Disassembly/reassembly correctness (2–4 months)
- [ ] Validate instruction coverage and code/data boundaries.
- [ ] Preserve relocation and import semantics where supported.
- [ ] Add section-level and whole-file comparisons.
- [ ] Test x86 and x64 separately.
**Exit:** fixture matrix with measured results and explicit exclusions.

## M4 — Directory coverage (3–6 months)
- [ ] Complete and test imports, exports, resources, relocations and TLS.
- [ ] Add debug, load-config and exception/unwind metadata where supported.
- [ ] Handle overlays and certificate tables; document signature invalidation on mutation.
**Exit:** each supported directory has parser/serializer tests.

## M5 — Release quality (1–2 months)
- [ ] CI across supported Python versions and operating systems.
- [ ] Fuzz malformed headers and directory ranges.
- [ ] Publish limitations, examples and versioned CLI docs.
**Exit:** reproducible release and documented test corpus.

## Schedule

| Period | Goal |
|---|---|
| Weeks 1–2 | M0 baseline |
| Weeks 3–7 | M1 parser hardening |
| Months 2–3 | M2 canonical representation |
| Months 3–6 | M3 round-trip validation |
| Months 6–12 | M4 directory coverage |
| Months 12–14 | M5 release hardening |

A universal bit-perfect PE round trip is not assumed. Compatibility must be stated per tested fixture and feature set.
