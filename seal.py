"""Authenticated file encryption (AES-256-GCM, streamed in 4 MiB blocks).

  python seal.py seal IN OUT     # key: base64 32 bytes in $BOX_KEY
  python seal.py open IN OUT

Layout: MAGIC | 12-byte nonce | ciphertext | 16-byte tag. Opening writes to OUT.partial and
renames only after the tag verifies, so a tampered or truncated box never yields output.
"""
import base64, os, sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"SBX1\n"
AAD = b"box/v1"
BLOCK = 1 << 22


def _key():
    k = base64.b64decode(os.environ["BOX_KEY"], validate=True)
    if len(k) != 32:
        raise ValueError("bad key length")
    return k


def seal(src, dst):
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(_key()), modes.GCM(nonce)).encryptor()
    enc.authenticate_additional_data(AAD)
    with open(src, "rb") as f, open(dst, "xb") as out:
        out.write(MAGIC + nonce)
        for block in iter(lambda: f.read(BLOCK), b""):
            out.write(enc.update(block))
        out.write(enc.finalize() + enc.tag)


def open_box(src, dst):
    src, dst = Path(src), Path(dst)
    size = src.stat().st_size
    if size < len(MAGIC) + 28:
        raise ValueError("box too small")
    tmp = dst.with_name(dst.name + ".partial")
    try:
        with src.open("rb") as f, tmp.open("xb") as out:
            if f.read(len(MAGIC)) != MAGIC:
                raise ValueError("bad header")
            nonce = f.read(12)
            f.seek(-16, 2); tag = f.read(16); f.seek(len(MAGIC) + 12)
            dec = Cipher(algorithms.AES(_key()), modes.GCM(nonce, tag)).decryptor()
            dec.authenticate_additional_data(AAD)
            left = size - len(MAGIC) - 28
            while left:
                block = f.read(min(BLOCK, left))
                if not block:
                    raise ValueError("truncated box")
                out.write(dec.update(block)); left -= len(block)
            out.write(dec.finalize())
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    cmd, a, b = sys.argv[1:4]
    {"seal": seal, "open": open_box}[cmd](a, b)
