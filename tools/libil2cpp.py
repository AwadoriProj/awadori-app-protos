"""Decrypt libil2cpp.so of com.bilibili.sirius 1.0.1-25 so IL2CPP tools can read it.

After the game loads libil2cpp.so, libanort.so decrypts three of its sections in memory
(sub_38434 -> 0x13FEE0, mode 1). The sections are listed in libanort.so's region table at
0x1C3CB0 (name, VA, file offset, size, segment VA/size/prot). On disk they stay encrypted,
so Il2CppInspector/Il2CppDumper read garbage from e.g. the generic method table in .rodata.

For each section of 1 MiB or more, starting at the second page boundary after its start:
  [+0x0000, +0x4000)   AES-128-CBC, 8 independent 0x800 chunks (same cipher as the metadata)
  [+0x4000, +0x10000)  unchanged
  from +0x10000        XOR the first 0x4000 bytes of every 64 KiB block with (SEED >> 16) & 0xFF,
                       and the whole trailing partial block
Smaller sections are XORed completely (0x156844).

    python libil2cpp.py decrypt libil2cpp.so libil2cpp.decrypted.so
    python libil2cpp.py find-seed libil2cpp.so     # recover SEED for another build (needs `cryptography`)
"""
import argparse
import struct
from pathlib import Path

from metadata import AES128, AES_IV, AES_CHUNK

# CHANGE [protector]: computed at runtime by sub_30A1C(tree, 1, name) in libanort.so, not stored
# in the clear. Recover it for another build with `find-seed`.
SEED = 0xBA981955
SECTIONS = (".rodata", ".text", "il2cpp")  # CHANGE [protector]: names in the region table (here libanort.so:0x1C3CB0)
SKIP_PAGES = 0x2000                        # CHANGE [protector]: 0x13FEE0 starts at VA + 0x2000 - (VA & 0xFFF)
AES_LEN = 0x4000                           # CHANGE [protector]: 8 x 0x800 chunks in 0x13E57C
STRIPE_START = 0x10000                     # CHANGE [protector]: 0x13E57C passes start + 0x10000 to 0x156870
STRIPE_BLOCK = 0x10000                     # CHANGE [protector]: block stride in 0x156870
STRIPE_LEN = 0x4000                        # CHANGE [protector]: XORed bytes at the start of each block in 0x156870
SMALL_SECTION = 0x100000                   # CHANGE [protector]: below this 0x13FEE0 XORs the whole section (0x156844)
# 0x156870 can also shuffle the stripes in groups of 8 (argument from libanort.so:0x196CD8), but that
# argument is 0 at runtime in this build: in-place stripes keep the generic method table in order.


def xor_key(seed):
    return (seed >> 16) & 0xFF or 0x87     # 0x87 when byte 2 of the seed is zero


def read_sections(data):
    """{name: (va, file offset, size)} from the ELF64 section headers."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    headers = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = headers[shstrndx][4]
    sections = {}
    for name_off, _, _, va, off, size in headers:
        name = data[strtab + name_off:data.index(b"\0", strtab + name_off)].decode()
        sections[name] = (va, off, size)
    return sections


def encrypted_ranges(va, off, size):
    """Yield (kind, file start, file end) for one protected section."""
    if size < SMALL_SECTION:
        yield "xor", off, off + size
        return
    skip = SKIP_PAGES - (va & 0xFFF)
    start, end = off + skip, off + size
    yield "aes", start, start + AES_LEN
    block = start + STRIPE_START
    while end - block >= STRIPE_BLOCK:
        yield "xor", block, block + STRIPE_LEN
        block += STRIPE_BLOCK
    yield "xor", block, end                # the trailing partial block is XORed completely


def decrypt(data, seed=SEED):
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("not a 64-bit ELF file")
    sections = read_sections(data)
    missing = [name for name in SECTIONS if name not in sections]
    if missing:
        raise ValueError(f"section(s) {', '.join(missing)} not found; not this build?")
    buf = bytearray(data)
    table = bytes(b ^ xor_key(seed) for b in range(256))
    aes = AES128(b"%08x%08x" % (seed, seed))
    for name in SECTIONS:
        for kind, start, end in encrypted_ranges(*sections[name]):
            if kind == "xor":
                buf[start:end] = buf[start:end].translate(table)
                continue
            for chunk in range(start, end, AES_CHUNK):
                buf[chunk:chunk + AES_CHUNK] = aes.cbc_decrypt(bytes(buf[chunk:chunk + AES_CHUNK]), AES_IV)
            # Ciphertext has ~1 zero byte in 256; the decrypted data and code have far more.
            if buf[start:end].count(0) < (end - start) // 64:
                raise ValueError(f"{name}: AES window still looks random; wrong SEED for this build")
    return bytes(buf)


def _fast_cbc_decrypt(seed, cipher):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = b"%08x%08x" % (seed, seed)
    return Cipher(algorithms.AES(key), modes.CBC(AES_IV)).decryptor().update(cipher)


def _seed_candidates(args):
    """Seeds with top byte `hi` whose first two AES blocks decrypt to float constants, text or zeros."""
    hi, key_byte, cipher = args
    hits = []
    for lo in range(0x10000):
        seed = hi << 24 | key_byte << 16 | lo
        plain = _fast_cbc_decrypt(seed, cipher)
        floats = sum(w == 0 or 0x60 <= (w >> 23) & 0xFF <= 0x9F for w in struct.unpack("<8I", plain))
        text = sum(32 <= b < 127 or b == 0 for b in plain)
        if floats >= 7 or text >= 28 or plain.count(0) >= 8:
            hits.append(seed)
    return hits


def find_seed(data):
    """Brute-force the 24 unknown seed bits against the AES window of the first large section.

    Byte 2 of the seed is the stripe XOR key: across all stripes the most common byte is an
    XORed zero (a single stripe can be text, where it would be an XORed 'e'). The other 24 bits
    are searched, and the candidates are ranked by zero bytes in a decrypted 0x800 chunk, where
    the right seed stands far above random output.
    """
    from collections import Counter
    from multiprocessing import Pool
    sections = read_sections(data)
    counts = Counter()
    for name in SECTIONS:
        for kind, start, end in encrypted_ranges(*sections[name]):
            if kind == "xor":
                counts.update(data[start:end])
    key_byte = counts.most_common(1)[0][0]
    first = next(sections[n] for n in SECTIONS if sections[n][2] >= SMALL_SECTION)
    _, aes_start, _ = next(encrypted_ranges(*first))
    jobs = [(hi, key_byte, data[aes_start:aes_start + 32]) for hi in range(256)]
    with Pool() as pool:
        candidates = [seed for hits in pool.map(_seed_candidates, jobs) for seed in hits]
    window = data[aes_start:aes_start + AES_CHUNK]
    return max(candidates, key=lambda seed: _fast_cbc_decrypt(seed, window).count(0), default=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("decrypt", "find-seed"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--seed", type=lambda s: int(s, 0), default=SEED, help=f"default {SEED:#010x}")
    args = parser.parse_args()
    try:
        data = args.input.read_bytes()
        if args.mode == "find-seed":
            seed = find_seed(data)
            print(f"seed: {seed:#010x}" if seed is not None else "no seed found")
            return
        if args.output is None:
            raise ValueError("an output path is required")
        if args.output.resolve() == args.input.resolve():
            raise ValueError("output must be a different file from input")
        args.output.write_bytes(decrypt(data, args.seed))
        print(f"wrote {len(data):,} bytes to {args.output}")
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
