import sys
import struct

def analyze(filename):
    with open(filename, "rb") as f:
        data = f.read()
    
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    sections_count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    sec_offset = pe + 24 + opt_size
    
    print(f"=== {filename} (Gesamtgröße: {len(data)} Bytes) ===")
    end_of_sections = 0
    for i in range(sections_count):
        off = sec_offset + i * 40
        name = data[off:off+8].rstrip(b"\0").decode("ascii", errors="ignore")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        print(f"  Section {name:<8} RawSize: 0x{rsize:X} ({rsize} B)  RawPtr: 0x{rptr:X}")
        end_of_sections = max(end_of_sections, rptr + rsize)
    
    overlay_size = len(data) - end_of_sections
    if overlay_size > 0:
        print(f"  [!] Extra Daten am Dateiende (Signatur/Overlay): {overlay_size} Bytes")
    print()

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        analyze(sys.argv[1])
        analyze(sys.argv[2])
    else:
        print("Nutzung: python compare.py <original.exe> <app.exe>")