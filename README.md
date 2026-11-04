# PEBuilder

PEBuilder is a Python toolkit for inspecting, disassembling and rebuilding Windows Portable Executable (PE) files. The project contains PE structure handling, assembly/disassembly helpers, directory support and binary comparison utilities.

> **Status: active experimental tooling.** Feature coverage and round-trip fidelity depend on the input binary and the implemented PE directory handlers. Treat byte-identical reconstruction as a per-fixture test result, not a universal guarantee.

## Capabilities represented in the codebase

- PE parsing and section metadata handling.
- x86/x64 disassembly and assembly integration through Capstone and Keystone.
- Helpers for imports, exports, relocations, resources, TLS and other PE metadata.
- Reassembly, overlays and binary/section comparison utilities.

Not every PE feature is necessarily supported for every architecture, linker, compiler or executable. Unsupported and malformed inputs should fail clearly rather than produce a misleading success result.

## Installation

Python 3.10+ is recommended. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install capstone keystone-engine
python -m pip install -e .
```

Confirm the package metadata and CLI entry points in the current checkout before relying on commands below; interfaces may evolve while the project is experimental.

## Validation principles

A successful parse or reassembly is not proof of semantic equivalence or executability. For each supported fixture, record:
- PE architecture, section layout and data directories.
- Whether output parses with an independent PE parser.
- Byte-level equality, including file length and overlay.
- Which directories are preserved, rebuilt or intentionally unsupported.
- Whether signatures are invalidated by modification.

Authenticode signatures generally cannot remain valid after binary modifications. Do not describe signed-file preservation unless verified separately.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for phased work, acceptance criteria and a provisional schedule.

## Safety and licensing

Only analyze binaries you are legally entitled to inspect. Do not commit proprietary executables, DLLs, extracted payloads, private test samples or generated binary blobs. Keep test inputs outside version control or use redistributable fixtures. Review the license and provenance of every dependency and contributed file before release.
