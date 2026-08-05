```markdown
# PEBuilder 🛠️

> **Standalone Bit-Perfect Portable Executable (PE) Disassembler & Reassembler Toolchain**

`pebuilder` is a Python framework designed to disassemble Windows PE binaries (`.exe` / `.dll` for 32-bit x86 and 64-bit x64), represent every section and metadata field in a human-readable `.asm` file, and reassemble it back into a **100% bit-perfect, bootable PE executable** — without needing the original binary at build time.

---

## ✨ Features

* **Bit-Perfect 1:1 Reconstruction**  
  Achieves 100.0000% byte-for-byte exact PE binary reconstruction (verified on 30MB+ commercial DirectX 11 executables).

* **Standalone Pipeline**  
  Disassembles PE binaries into self-contained `.asm` listings containing all required PE headers, metadata, section flags, data directories, DOS stubs, and overlays.

* **Multi-Section Support**  
  Preserves `.text`, `.rdata`, `.data`, `.pdata`, `.tls`, `.rsrc`, `.reloc`, and custom sections with exact VirtualSizes and characteristics.

* **PE Directory Preservation**  
  Maintains all 15 Data Directories (Imports, Exports, Resources, Exception Handling, Security/Signatures, TLS, LoadConfig, IAT, Debug, etc.).

* **x86 & x64 Architecture Support**  
  Powered by the Capstone Disassembler and Keystone Engine Assembler backends.

* **Overlay & DOS Stub Preservation**  
  Fully preserves digital signatures, overlays, and custom MSVC Rich Headers / DOS stubs.

---

## ⚙️ Installation

1. Activate your Python virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

2. Install the required dependencies:
   ```powershell
   pip install capstone keystone-engine
   ```

3. Install `pebuilder` in editable mode:
   ```powershell
   pip install -e .
   ```

---

## 🚀 Quick Start

### Step 1: Disassemble a Binary
Disassemble any `.exe` or `.dll` into a standalone `.asm` file:
```powershell
python .\pebuilder\disassemble.py C:\path\to\target.exe -o target.asm
```

### Step 2: Reassemble into an Executable
Rebuild a bootable, bit-perfect executable directly from the `.asm` file (no original binary required):
```powershell
python -m pebuilder.reassembler --disasm target.asm --output target_rebuilt.exe
```

### Step 3: Verify 1:1 Equivalence
Compare the original binary with the rebuilt binary byte-by-byte:
```powershell
python -c "b1=open(r'C:\path\to\target.exe','rb').read(); b2=open('target_rebuilt.exe','rb').read(); diff=sum(1 for x,y in zip(b1,b2) if x!=y); print(f'Byte Differences: {diff} / {len(b1)} (Match: {(len(b1)-diff)/len(b1)*100:.6f}%)')"
```

---

## 📂 Project Structure

```text
pebuilder/
├── pebuilder/
│   ├── __init__.py         # Package initialization
│   ├── pe.py               # Low-level PE structures & NT header packing
│   ├── builder.py          # PE Builder engine
│   ├── linker.py           # PE Linker & Data Directory collector
│   ├── sections.py         # PESection & SectionTable alignment managers
│   ├── assembler.py        # Keystone assembler backend & listing parser
│   ├── disassemble.py      # Capstone disassembler & PE metadata exporter
│   ├── reassembler.py      # Standalone CLI reassembler
│   ├── compare.py          # PE Section comparison utility
│   ├── check_pe.py         # PE Header & Directory diagnostic tool
│   ├── find_diffs.py       # Byte-level difference analyzer
│   ├── fix_overlay.py      # Overlay & signature helper
│   ├── overlay.py          # PE Overlay handler
│   ├── resources.py        # Resource section handler
│   ├── imports.py          # Import Directory builder
│   ├── exports.py          # Export Directory builder
│   ├── reloc.py            # Relocation Directory builder
│   ├── tls.py              # TLS Directory handler
│   ├── pdata.py            # x64 Unwind Info builder
│   ├── debug.py            # Debug Directory handler
│   └── loadconfig.py       # Load Config Directory handler
├── .gitignore              # Git ignore configuration
├── README.md               # Project documentation
└── setup.py                # Package setup script
```

---

## 🔒 License

Private Repository. All rights reserved.
```