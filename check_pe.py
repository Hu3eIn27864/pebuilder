import struct
import sys

def check_pe_headers(orig_path, app_path):
    def parse_header(path):
        with open(path, "rb") as f:
            data = f.read()

        pe_off = struct.unpack_from("<I", data, 0x3c)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        
        is_64 = (magic == 0x20b)
        entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<Q" if is_64 else "<I", data, opt_off + 24)[0]
        subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        num_dirs = struct.unpack_from("<I", data, opt_off + (108 if is_64 else 92))[0]
        
        dir_base = opt_off + (112 if is_64 else 96)
        dirs = {}
        dir_names = [
            "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
            "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
            "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR"
        ]
        
        for i in range(min(num_dirs, 15)):
            rva, size = struct.unpack_from("<II", data, dir_base + i * 8)
            name = dir_names[i] if i < len(dir_names) else f"DIR_{i}"
            dirs[name] = (rva, size)
            
        return {
            "entry_point": entry_point,
            "image_base": image_base,
            "subsystem": subsystem,
            "dirs": dirs
        }

    orig = parse_header(orig_path)
    app = parse_header(app_path)

    app_name = sys.argv[2] if len(sys.argv) > 2 else "app.exe"
    print(f"{'Header / Directory':<20} | {'Original':<30} | {app_name:<30} | Status")
    print("-" * 95)
    print(f"{'EntryPoint RVA':<20} | 0x{orig['entry_point']:<28X} | 0x{app['entry_point']:<28X} | {'OK' if orig['entry_point'] == app['entry_point'] else 'MISMATCH!'}")
    print(f"{'ImageBase':<20} | 0x{orig['image_base']:<28X} | 0x{app['image_base']:<28X} | {'OK' if orig['image_base'] == app['image_base'] else 'MISMATCH!'}")
    print(f"{'Subsystem':<20} | {orig['subsystem']:<30} | {app['subsystem']:<30} | {'OK' if orig['subsystem'] == app['subsystem'] else 'MISMATCH!'}")
    print("-" * 95)

    for name in orig['dirs']:
        o_rva, o_size = orig['dirs'][name]
        a_rva, a_size = app['dirs'].get(name, (0, 0))
        match = "OK" if (o_rva == a_rva and o_size == a_size) else "MISMATCH!"
        print(f"{name:<20} | RVA: 0x{o_rva:<8X} Size: 0x{o_size:<8X} | RVA: 0x{a_rva:<8X} Size: 0x{a_size:<8X} | {match}")

if __name__ == "__main__":
    orig_p = sys.argv[1] if len(sys.argv) > 1 else r"..\LCU\LEGOLCUR_DX11.exe"
    app_p = sys.argv[2] if len(sys.argv) > 2 else "app.exe"
    check_pe_headers(orig_p, app_p)