#!/usr/bin/env python3
import sys
import subprocess
import pgpy
import pgpy.constants as C
from pgpy.constants import PubKeyAlgorithm, EllipticCurveOID


def get_xy_hex():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == '/dev/stdin' or arg == '-':
            return sys.stdin.read().strip()
        return arg.strip()
    return input("Paste hex public key (X||Y, 128 characters hex): ").strip()


def build_cert(xy_hex: str) -> bytes:
    xy = bytes.fromhex(xy_hex)
    assert len(xy) == 64, f"Expected 64B, got {len(xy)}B"

    x = int.from_bytes(xy[:32], 'big')
    y = int.from_bytes(xy[32:], 'big')

    key = pgpy.PGPKey.new(PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256)

    subkey = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.NIST_P256)
    km = subkey._key.keymaterial
    km.p.x = pgpy.packet.fields.MPI(x)
    km.p.y = pgpy.packet.fields.MPI(y)

    uid = pgpy.PGPUID.new('Pico Device', email='pico@device')
    key.add_uid(uid, usage={C.KeyFlags.Sign}, hashes=[C.HashAlgorithm.SHA256], ciphers=[C.SymmetricKeyAlgorithm.AES256])

    key.add_subkey(subkey, usage={C.KeyFlags.EncryptCommunications})

    return bytes(key.pubkey)


def import_to_gpg(cert_path: str) -> None:
    r_del = subprocess.run(
        ['gpg', '--batch', '--yes', '--delete-keys', 'pico@device'],
        capture_output=True, text=True)
    if r_del.returncode == 0:
        print("\t[*] Deleted old pico@device certificates from keyring")

    r = subprocess.run(
        ['gpg', '--import', cert_path],
        capture_output=True, text=True)

    for line in r.stderr.split('\n'):
        if line.strip():
            print(f"\t{line}")

    if r.returncode != 0:
        raise RuntimeError(f"gpg --import failed:\n{r.stderr}")


def get_subkey_fingerprint_from_gpg(uid_email: str) -> bytes:
    r = subprocess.run(
        ['gpg', '--list-keys', '--with-subkey-fingerprints',
         '--with-colons', uid_email],
        capture_output=True, text=True)

    if r.returncode != 0:
        raise RuntimeError(
            f"gpg --list-keys failed. Does the certificate was imported?\n{r.stderr}")

    fprs = [line.split(':')[9]
            for line in r.stdout.split('\n')
            if line.startswith('fpr')]

    if len(fprs) < 2:
        raise RuntimeError(
            f"Subkey fingerprint not found.\n"
            f"Found fpr lines: {fprs}\n"
            f"Full GPG output:\n{r.stdout}")

    subkey_fp_hex = fprs[1]  

    if len(subkey_fp_hex) != 40:
        raise RuntimeError(
            f"Invalid fingerprint length: {len(subkey_fp_hex)} characters "
            f"(expected 40)")

    return bytes.fromhex(subkey_fp_hex)


def save_fingerprint(fp_bytes: bytes, fp_path: str) -> None:
    assert len(fp_bytes) == 20
    with open(fp_path, 'wb') as f:
        f.write(fp_bytes)


def main():
    cert_path = 'pico_cert.pgp'
    fp_path = 'pico_cert.pgp.fp'
    uid_email = 'pico@device'

    xy_hex = get_xy_hex()
    print(f"\n[*] Public Key P-256:")
    print(f"\tX: {xy_hex[:64]}")
    print(f"\tY: {xy_hex[64:]}")

    print(f"\n[*] Building PGP certificate...")
    cert_bytes = build_cert(xy_hex)
    with open(cert_path, 'wb') as f:
        f.write(cert_bytes)
    print(f"\tCertificate: {cert_path} ({len(cert_bytes)}B)")

    print(f"\n[*] Importing to GPG keyring...")
    import_to_gpg(cert_path)

    print(f"\n[*] Fetching subkey fingerprint from GPG...")
    subkey_fp = get_subkey_fingerprint_from_gpg(uid_email)

    save_fingerprint(subkey_fp, fp_path)

    print(f"\n{'='*60}")
    print(f"[+] Finished")
    print(f"\tCertificate: {cert_path} ({len(cert_bytes)}B)")
    print(f"\tFingerprint: {fp_path} ({len(subkey_fp)}B)")
    print(f"\tSubkey FP: {subkey_fp.hex().upper()}")
    print(f"\tKey ID: {subkey_fp[-8:].hex().upper()}")
    print(f"{'='*60}")
    print()
    print("Now you can encrypt:")
    print(f"\tpico-pgp encrypt plik.txt")
    print()
    print("And decrypt:")
    print(f"\tpico-pgp decrypt plik.txt.pgp")


if __name__ == '__main__':
    main()