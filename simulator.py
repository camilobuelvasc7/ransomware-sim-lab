import argparse, os, shutil, time, base64, hashlib, json
from pathlib import Path

NOTE_TEXT = """YOUR FILES ARE ENCRYPTED (SIMULATION)
This is a SAFE educational simulation. No real data is harmed.
To 'recover' files, run: python simulator.py --decrypt --key {key}
"""

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def write_log(log_path, event, details):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, "details": details}) + "\n")

def simulate_encryption(src_dir: Path, out_dir: Path, key_b: bytes, log_path: Path, ext: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    for root, _, files in os.walk(src_dir):
        rel_root = Path(root).relative_to(src_dir)
        (out_dir / rel_root).mkdir(parents=True, exist_ok=True)
        for fn in files:
            src = Path(root) / fn
            dst = out_dir / rel_root / f"{fn}.{ext}"
            with open(src, "rb") as f:
                data = f.read()
            enc = xor_bytes(data, key_b)
            with open(dst, "wb") as f:
                f.write(enc)
            write_log(log_path, "encrypt_file", {"src": str(src), "dst": str(dst), "size": len(data)})

def simulate_note(out_dir: Path, key_hex: str, log_path: Path):
    note = out_dir / "README_TO_DECRYPT.txt"
    note.write_text(NOTE_TEXT.format(key=key_hex), encoding="utf-8")
    write_log(log_path, "write_note", {"note": str(note)})

def simulate_persistence(out_dir: Path, log_path: Path):
    marker = out_dir / ".persistence_marker"
    marker.write_text("Simulated persistence record only.", encoding="utf-8")
    task_xml = out_dir / "simulated_schtask.xml"
    task_xml.write_text(
        """<Task version="1.2"><RegistrationInfo><Description>Simulated</Description></RegistrationInfo></Task>""",
        encoding="utf-8",
    )
    write_log(log_path, "simulate_persistence", {"files": [str(marker), str(task_xml)]})

def decrypt(out_dir: Path, key_b: bytes, ext: str, log_path: Path):
    for p in out_dir.rglob(f"*.{ext}"):
        with open(p, "rb") as f:
            enc = f.read()
        dec = xor_bytes(enc, key_b)
        orig = p.with_suffix("")  # remove .ext
        with open(orig, "wb") as f:
            f.write(dec)
        p.unlink()
        write_log(log_path, "decrypt_file", {"restored": str(orig)})

def main():
    ap = argparse.ArgumentParser(description="Safe ransomware-behaviour simulator (lab-only).")
    ap.add_argument("--lab-dir", default="lab_output", help="Output folder for simulated impact.")
    ap.add_argument("--source", default="sample_data", help="Folder with harmless demo files to encrypt.")
    ap.add_argument("--ext", default="locked", help="Extension to append to simulated encrypted files.")
    ap.add_argument("--key", default=None, help="Passphrase to derive key (if omitted, demo default).")
    ap.add_argument("--decrypt", action="store_true", help="Decrypt previously simulated files.")
    args = ap.parse_args()

    lab = Path(args.lab_dir)
    src = Path(args.source)
    log_path = lab / "ransomware_behavior.log"
    lab.mkdir(parents=True, exist_ok=True)

    passphrase = args.key if args.key is not None else "DEMO-LOCKBIT-LIKE-KEY"
    key_b = derive_key(passphrase)
    key_hex = base64.urlsafe_b64encode(key_b).decode()

    write_log(log_path, "start", {"mode": "decrypt" if args.decrypt else "encrypt", "passphrase_present": args.key is not None})

    if args.decrypt:
        decrypt(lab, key_b, args.ext, log_path)
    else:
        working = lab / "working_copy"
        if working.exists():
            shutil.rmtree(working)
        shutil.copytree(src, working)
        write_log(log_path, "prep_working_copy", {"from": str(src), "to": str(working)})

        simulate_encryption(working, lab, key_b, log_path, args.ext)
        simulate_note(lab, key_hex, log_path)
        simulate_persistence(lab, log_path)

    write_log(log_path, "done", {})
    print(f"[OK] Log: {log_path}")
    print(f"[OK] Lab dir: {lab.resolve()}")

if __name__ == "__main__":
    main()
