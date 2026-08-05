import struct
import sys

def full_compare(orig_path, app_path):
    with open(orig_path, "rb") as f:
        d1 = f.read()
    with open(app_path, "rb") as f:
        d2 = f.read()

    pe1 = struct.unpack_from("<I", d1, 0x3c)[0]
    pe2 = struct.unpack_from("<I", d2, 0x3c)[0]

    opt1 = pe1 + 24
    opt2 = pe2 + 24

    size_image1 = struct.unpack_from("<I", d1, opt1 + 56)[0]
    size_image2 = struct.unpack_from("<I", d2, opt2 + 56)[0]

    dll_char1 = struct.unpack_from("<H", d1, opt1 + 70)[0]
    dll_char2 = struct.unpack_from("<H", d2, opt2 + 70)[0]

    print(f"SizeOfImage:        0x{size_image1:X} vs 0x{size_image2:X} -> {'OK' if size_image1 == size_image2 else 'MISMATCH'}")
    print(f"DllCharacteristics: 0x{dll_char1:04X} vs 0x{dll_char2:04X} -> {'OK' if dll_char1 == dll_char2 else 'MISMATCH (Original=0x{:04X}, Rebuilt=0x{:04X})'.format(dll_char1, dll_char2)}")

    sec1_cnt = struct.unpack_from("<H", d1, pe1 + 6)[0]
    sec2_cnt = struct.unpack_from("<H", d2, pe2 + 6)[0]

    opt1_sz = struct.unpack_from("<H", d1, pe1 + 20)[0]
    opt2_sz = struct.unpack_from("<H", d2, pe2 + 20)[0]

    st1 = opt1 + opt1_sz
    st2 = opt2 + opt2_sz

    print("\nSektions-Rechte (Characteristics):")
    for i in range(sec1_cnt):
        off1 = st1 + i * 40
        off2 = st2 + i * 40
        name1 = d1[off1:off1+8].rstrip(b"\0").decode("ascii", "ignore")
        name2 = d2[off2:off2+8].rstrip(b"\0").decode("ascii", "ignore")
        char1 = struct.unpack_from("<I", d1, off1 + 36)[0]
        char2 = struct.unpack_from("<I", d2, off2 + 36)[0]
        match = "OK" if char1 == char2 else f"MISMATCH (Original=0x{char1:08X}, Rebuilt=0x{char2:08X})"
        print(f"  {name1:<8}: {match}")

if __name__ == "__main__":
    orig = sys.argv[1] if len(sys.argv) > 1 else r"..\LCU\LEGOLCUR_DX11.exe"
    app = sys.argv[2] if len(sys.argv) > 2 else "app_standalone.exe"
    full_compare(orig, app)