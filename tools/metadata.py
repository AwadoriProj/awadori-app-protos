"""Decrypt / re-encrypt global-metadata.dat of com.bilibili.sirius 1.0.1-25 (Unity 6000.3.12f1, ARM64).

libanort.so hooks the mmap that libil2cpp uses to map the metadata (0x152594). When the
file starts with 0x12724394 it reads the whole file, decodes it with 0x156638 using the
seed 0xD96603C0, and then zeroes the sanity/version words so a memory dump has no
recognisable header. The packer had already replaced those 8 bytes in the file, so they
are rebuilt here as the stock IL2CPP values: sanity 0xFAB11BAF, version 39.

    python metadata.py decrypt global-metadata.dat global-metadata.decrypted.dat
    python metadata.py encrypt global-metadata.decrypted.dat global-metadata.dat
    python metadata.py info global-metadata.decrypted.dat
"""
import argparse
import struct
from pathlib import Path

# Values marked CHANGE need re-checking for another build. [protector] values come from
# libanort.so (addresses are for this build), [unity] values depend on the Unity version.

SEED = 0xD96603C0                          # CHANGE [protector]: MOV/MOVK W2 before the BL to 0x156638 (here libanort.so:0x15271C)
XOR_KEY = (SEED >> 16) & 0xFF              # derived from SEED (0x66); CHANGE only if 0x156638 picks a different byte
AES_KEY = b"%08x%08x" % (SEED, SEED)       # derived from SEED; CHANGE only if the format string at 0x1567A4 changes
AES_IV = bytes(range(0x02, 0x12))          # CHANGE [protector]: 16 bytes loaded in 0x13E37C (here libanort.so:0x190060)
AES_START, AES_END, AES_CHUNK = 0x1000, 0x5000, 0x800  # CHANGE [protector]: args of the 0x13E448 call in 0x156638
XOR_STRIPE_START = 0x11000                 # CHANGE [protector]: first striped block in 0x156638
XOR_STRIPE_BLOCK = 0x10000                 # CHANGE [protector]: stride between stripes in 0x156638
XOR_STRIPE_LEN = 0x4000                    # CHANGE [protector]: XORed bytes at the start of each stripe
SMALL_FILE = 0x100000                      # CHANGE [protector]: below this size 0x156638 only XORs [8, EOF)

PROTECTED_MAGIC = 0x12724394               # CHANGE [protector]: dword the mmap hook compares with the pread() result
PACKER_TAG = bytes.fromhex("184b9eec")     # CHANGE [protector]: bytes 4..8 of the new protected file (only used by encrypt)
IL2CPP_SANITY = 0xFAB11BAF                 # fixed by IL2CPP, never changes
# CHANGE [unity]: read the Unity version from assets/bin/Data/data.unity3d and map it,
# e.g. 2022.3.33-6000.2 -> 31, 6000.3 -> 39, 6000.5 -> 104+ (see Il2CppInspectorRedux's README).
METADATA_VERSION = 39
# CHANGE [unity]: equals the first section offset (bytes 8..12 once decoded). v38+ uses
# 12-byte {offset, size, count} triples; v31 and older use 8-byte {offset, size} pairs,
# which also means changing the section parsing in read_sections().
HEADER_SIZE = 8 + 31 * 12
SECTION_NAMES = (  # CHANGE [unity]: section order/count of Il2CppGlobalMetadataHeader for METADATA_VERSION
    "stringLiterals", "stringLiteralData", "strings", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies", "fieldRefs",
    "referencedAssemblies", "attributeData", "attributeDataRanges",
    "unresolvedIndirectCallParameterTypes", "unresolvedIndirectCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
)


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _gmul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _make_sboxes():
    sbox = []
    for x in range(256):
        inv = next((y for y in range(1, 256) if _gmul(x, y) == 1), 0)
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox.append(s ^ 0x63)
    inv_sbox = [0] * 256
    for x, s in enumerate(sbox):
        inv_sbox[s] = x
    return sbox, inv_sbox


SBOX, INV_SBOX = _make_sboxes()
MUL = {f: [_gmul(x, f) for x in range(256)] for f in (1, 2, 3, 9, 11, 13, 14)}


def _mix_columns(state, coefficients):
    tables = [MUL[c] for c in coefficients]
    out = []
    for c in range(0, 16, 4):
        column = state[c:c + 4]
        for row in range(4):
            value = 0
            for j in range(4):
                value ^= tables[(j - row) % 4][column[j]]
            out.append(value)
    return out


class AES128:
    """Plain AES-128 so the script has no dependencies; only 0x4000 bytes go through it."""

    def __init__(self, key):
        words = list(key)
        rcon = 1
        for i in range(16, 176, 4):
            temp = words[i - 4:i]
            if i % 16 == 0:
                temp = [SBOX[b] for b in temp[1:] + temp[:1]]
                temp[0] ^= rcon
                rcon = _xtime(rcon)
            words += [a ^ b for a, b in zip(words[i - 16:i - 12], temp)]
        self.round_keys = [words[i:i + 16] for i in range(0, 176, 16)]

    def encrypt_block(self, block):
        state = [a ^ b for a, b in zip(block, self.round_keys[0])]
        for rnd in range(1, 11):
            state = [SBOX[state[(i + 4 * (i % 4)) % 16]] for i in range(16)]
            if rnd != 10:
                state = _mix_columns(state, (2, 3, 1, 1))
            state = [a ^ b for a, b in zip(state, self.round_keys[rnd])]
        return bytes(state)

    def decrypt_block(self, block):
        state = [a ^ b for a, b in zip(block, self.round_keys[10])]
        for rnd in range(9, -1, -1):
            state = [INV_SBOX[state[(i - 4 * (i % 4)) % 16]] for i in range(16)]
            state = [a ^ b for a, b in zip(state, self.round_keys[rnd])]
            if rnd:
                state = _mix_columns(state, (14, 11, 13, 9))
        return bytes(state)

    def cbc_encrypt(self, data, iv):
        out, prev = bytearray(), iv
        for i in range(0, len(data), 16):
            prev = self.encrypt_block(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
            out += prev
        return bytes(out)

    def cbc_decrypt(self, data, iv):
        out, prev = bytearray(), iv
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            out += bytes(a ^ b for a, b in zip(self.decrypt_block(block), prev))
            prev = block
        return bytes(out)


def xor_ranges(size):
    """File ranges XORed by libanort.so:0x156638."""
    if size < SMALL_FILE:
        yield 8, size
        return
    yield 8, AES_START
    start = XOR_STRIPE_START
    while size - start >= XOR_STRIPE_BLOCK:
        yield start, start + XOR_STRIPE_LEN
        start += XOR_STRIPE_BLOCK
    yield start, size                  # the trailing partial block is XORed completely


def apply_codec(buf, decrypt):
    """In-place transform of everything after byte 8. XOR and AES ranges do not overlap."""
    table = bytes(b ^ XOR_KEY for b in range(256))
    for start, end in xor_ranges(len(buf)):
        buf[start:end] = buf[start:end].translate(table)
    if len(buf) >= SMALL_FILE:
        aes = AES128(AES_KEY)
        for start in range(AES_START, AES_END, AES_CHUNK):
            chunk = bytes(buf[start:start + AES_CHUNK])
            buf[start:start + AES_CHUNK] = (aes.cbc_decrypt if decrypt else aes.cbc_encrypt)(chunk, AES_IV)


def read_sections(data):
    if len(data) < HEADER_SIZE:
        raise ValueError("file is smaller than the metadata header")
    # CHANGE [unity]: "<iii" / 12 is the v38+ triple. v31 and older are "<ii" / 8 {offset, size}
    # pairs, which also means dropping `count` from the unpacking here and in main().
    sections = [struct.unpack_from("<iii", data, 8 + i * 12) for i in range(len(SECTION_NAMES))]
    if sections[0][0] != HEADER_SIZE:
        raise ValueError("first section does not start right after the header; wrong key or not this build")
    for name, (offset, size, count) in zip(SECTION_NAMES, sections):
        if offset < HEADER_SIZE or size < 0 or count < 0 or offset + size > len(data):
            raise ValueError(f"section {name} is out of bounds; wrong key or not this build")
    return sections


def decrypt(data):
    if len(data) < HEADER_SIZE or struct.unpack_from("<I", data)[0] != PROTECTED_MAGIC:
        raise ValueError("input does not start with the protected magic 94 43 72 12")
    buf = bytearray(data)
    apply_codec(buf, decrypt=True)
    struct.pack_into("<II", buf, 0, IL2CPP_SANITY, METADATA_VERSION)
    read_sections(buf)
    if encrypt(buf, tag=data[4:8]) != data:
        raise ValueError("re-encrypting the result does not reproduce the input")
    return bytes(buf)


def encrypt(data, tag=PACKER_TAG):
    if struct.unpack_from("<I", data)[0] != IL2CPP_SANITY:
        raise ValueError("input does not start with AF 1B B1 FA; expected a decrypted file")
    read_sections(data)
    buf = bytearray(data)
    struct.pack_into("<I", buf, 0, PROTECTED_MAGIC)
    buf[4:8] = tag
    apply_codec(buf, decrypt=False)
    return bytes(buf)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("decrypt", "encrypt", "info"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        data = args.input.read_bytes()
        if args.mode == "info":
            sanity, version = struct.unpack_from("<II", data)
            print(f"sanity=0x{sanity:08X} version={version}")
            for name, (offset, size, count) in zip(SECTION_NAMES, read_sections(data)):
                print(f"{name:40} offset=0x{offset:08X} size={size:10} count={count:10}")
            return
        if args.output is None:
            raise ValueError("an output path is required")
        if args.output.resolve() == args.input.resolve():
            raise ValueError("output must be a different file from input")
        output = decrypt(data) if args.mode == "decrypt" else encrypt(data)
        args.output.write_bytes(output)
        print(f"wrote {len(output):,} bytes to {args.output} (header {output[:8].hex(' ').upper()})")
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
