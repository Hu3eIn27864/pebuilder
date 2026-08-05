import struct
import sys

def fix_exe(original_path, target_path):
    # 1. Original-EXE einlesen
    with open(original_path, "rb") as f:
        orig_data = f.read()

    pe_off = struct.unpack_from("<I", orig_data, 0x3c)[0]
    sec_count = struct.unpack_from("<H", orig_data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", orig_data, pe_off + 20)[0]
    sec_table = pe_off + 24 + opt_size

    orig_end_of_sections = 0
    for i in range(sec_count):
        off = sec_table + i * 40
        rsize, rptr = struct.unpack_from("<II", orig_data, off + 16)
        orig_end_of_sections = max(orig_end_of_sections, rptr + rsize)

    # Exaktes Original-Overlay extrahieren
    overlay_data = orig_data[orig_end_of_sections:]

    # 2. Ziel-Datei app.exe einlesen
    with open(target_path, "rb") as f:
        target_data = f.read()

    pe_off_t = struct.unpack_from("<I", target_data, 0x3c)[0]
    sec_count_t = struct.unpack_from("<H", target_data, pe_off_t + 6)[0]
    opt_size_t = struct.unpack_from("<H", target_data, pe_off_t + 20)[0]
    sec_table_t = pe_off_t + 24 + opt_size_t

    target_end_of_sections = 0
    for i in range(sec_count_t):
        off = sec_table_t + i * 40
        rsize, rptr = struct.unpack_from("<II", target_data, off + 16)
        target_end_of_sections = max(target_end_of_sections, rptr + rsize)

    # 3. app.exe exakt am Sektionsende abschneiden & Original-Overlay anfügen
    clean_target = target_data[:target_end_of_sections] + overlay_data

    with open(target_path, "wb") as f:
        f.write(clean_target)

    print(f"Fertig! Neue Gesamtgröße von {target_path}: {len(clean_target)} Bytes")

if __name__ == "__main__":
    orig = sys.argv[1] if len(sys.argv) > 1 else r"..\LCU\LEGOLCUR_DX11.exe"
    target = sys.argv[2] if len(sys.argv) > 2 else "app.exe"
    fix_exe(orig, target)