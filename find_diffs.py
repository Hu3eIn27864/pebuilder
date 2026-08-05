import struct
import sys

def find_diffs(orig_path, app_path):
    with open(orig_path, "rb") as f:
        b1 = f.read()
    with open(app_path, "rb") as f:
        b2 = f.read()

    pe1 = struct.unpack_from("<I", b1, 0x3c)[0]
    sec1_cnt = struct.unpack_from("<H", b1, pe1 + 6)[0]
    opt1_sz = struct.unpack_from("<H", b1, pe1 + 20)[0]
    st1 = pe1 + 24 + opt1_sz

    sections = []
    for i in range(sec1_cnt):
        off = st1 + i * 40
        name = b1[off:off+8].rstrip(b"\0").decode("ascii", "ignore")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", b1, off + 8)
        sections.append((name, rptr, rptr + rsize))

    diff_map = {}
    first_diffs = []
    for idx, (x, y) in enumerate(zip(b1, b2)):
        if x != y:
            sec_found = "Header/Padding"
            for sname, start, end in sections:
                if start <= idx < end:
                    sec_found = sname
                    break
            diff_map[sec_found] = diff_map.get(sec_found, 0) + 1
            if len(first_diffs) < 5:
                first_diffs.append((idx, sec_found, hex(x), hex(y)))

    print("Differenz-Analyse (Wo liegen die 538 Bytes?):")
    print("-" * 55)
    for sec_name, count in diff_map.items():
        print(f"  Sektion {sec_name:<10}: {count} abweichende Bytes")

    print("\nErste 5 Abweichungen (Offset, Sektion, Orig, Rebuilt):")
    for offset, sec, orig_val, re_val in first_diffs:
        print(f"  Offset 0x{offset:X} ({sec}): Original {orig_val} != Rebuilt {re_val}")

if __name__ == "__main__":
    orig = sys.argv[1] if len(sys.argv) > 1 else r"..\LCU\LEGOLCUR_DX11.exe"
    app = sys.argv[2] if len(sys.argv) > 2 else "app_standalone.exe"
    find_diffs(orig, app)