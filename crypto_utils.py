"""
crypto_utils.py
================
Wrapper implementasi ASCON-128 AEAD (pemenang NIST Lightweight Cryptography)
beserta pengelolaan kunci dan nonce.

Karena lingkungan eksekusi tidak memiliki akses jaringan untuk memasang
pustaka pihak ketiga (mis. `pyascon`/`ascon`), modul ini menyertakan
implementasi referensi ASCON v1.2 murni Python (tanpa dependensi eksternal),
mengikuti spesifikasi resmi algoritma (state 320-bit, permutasi 12/6 ronde,
rate 64-bit untuk varian Ascon-128). Implementasi ini divalidasi terhadap
test vector resmi NIST LWC pada bagian `_self_test()`.

API publik:
generate_key() -> bytes            # kunci 128-bit acak
generate_nonce() -> bytes          # nonce 128-bit acak
encrypt(key, nonce, plaintext, associated_data=b"") -> bytes  # ciphertext||tag
decrypt(key, nonce, ciphertext_and_tag, associated_data=b"") -> bytes | None
"""

import os

MASK64 = 0xFFFFFFFFFFFFFFFF
RATE_BYTES = 8      # rate 64-bit -> Ascon-128
ROUNDS_A = 12        # ronde permutasi awal & akhir
ROUNDS_B = 6         # ronde permutasi antar-blok
KEY_BYTES = 16
NONCE_BYTES = 16
TAG_BYTES = 16


# ---------------------------------------------------------------------------
# Primitif dasar
# ---------------------------------------------------------------------------

def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def _int_to_bytes(x: int, length: int = 8) -> bytes:
    return (x & MASK64).to_bytes(length, byteorder="big")


def _sbox_layer(S):
    S[0] ^= S[4]
    S[4] ^= S[3]
    S[2] ^= S[1]
    t = [((S[i] ^ MASK64) & S[(i + 1) % 5]) for i in range(5)]
    for i in range(5):
        S[i] ^= t[(i + 1) % 5]
    S[1] ^= S[0]
    S[0] ^= S[4]
    S[3] ^= S[2]
    S[2] ^= MASK64


def _linear_layer(S):
    S[0] ^= _rotr(S[0], 19) ^ _rotr(S[0], 28)
    S[1] ^= _rotr(S[1], 61) ^ _rotr(S[1], 39)
    S[2] ^= _rotr(S[2], 1) ^ _rotr(S[2], 6)
    S[3] ^= _rotr(S[3], 10) ^ _rotr(S[3], 17)
    S[4] ^= _rotr(S[4], 7) ^ _rotr(S[4], 41)


def _permutation(S, rounds: int):
    for r in range(12 - rounds, 12):
        rc = (0xF0 - r * 0x10 + r * 0x01) & MASK64
        S[2] ^= rc
        _sbox_layer(S)
        _linear_layer(S)


# ---------------------------------------------------------------------------
# Inisialisasi, absorbsi AD, enkripsi/dekripsi plaintext, finalisasi
# ---------------------------------------------------------------------------

def _initialize(key: bytes, nonce: bytes):
    k_bits = len(key) * 8
    iv = bytes([k_bits, RATE_BYTES * 8, ROUNDS_A, ROUNDS_B]) + bytes(4)
    S = [
        _bytes_to_int(iv),
        _bytes_to_int(key[0:8]),
        _bytes_to_int(key[8:16]),
        _bytes_to_int(nonce[0:8]),
        _bytes_to_int(nonce[8:16]),
    ]
    _permutation(S, ROUNDS_A)
    S[3] ^= _bytes_to_int(key[0:8])
    S[4] ^= _bytes_to_int(key[8:16])
    return S


def _pad(data: bytes, rate: int) -> bytes:
    last_len = len(data) % rate
    pad_len = rate - last_len - 1
    return data + b"\x80" + bytes(pad_len)


def _process_associated_data(S, associated_data: bytes):
    if len(associated_data) > 0:
        padded = _pad(associated_data, RATE_BYTES)
        for block_start in range(0, len(padded), RATE_BYTES):
            block = padded[block_start:block_start + RATE_BYTES]
            S[0] ^= _bytes_to_int(block)
            _permutation(S, ROUNDS_B)
    S[4] ^= 1


def _process_plaintext_encrypt(S, plaintext: bytes) -> bytes:
    last_len = len(plaintext) % RATE_BYTES
    padded = _pad(plaintext, RATE_BYTES)
    ciphertext = bytearray()
    n_blocks = len(padded) // RATE_BYTES
    for i in range(n_blocks - 1):
        block = padded[i * RATE_BYTES:(i + 1) * RATE_BYTES]
        S[0] ^= _bytes_to_int(block)
        ciphertext += _int_to_bytes(S[0], RATE_BYTES)
        _permutation(S, ROUNDS_B)
    # blok terakhir (dipotong sesuai panjang asli)
    block = padded[(n_blocks - 1) * RATE_BYTES: n_blocks * RATE_BYTES]
    S[0] ^= _bytes_to_int(block)
    last_c = _int_to_bytes(S[0], RATE_BYTES)
    ciphertext += last_c[:last_len] if len(plaintext) > 0 else b""
    if len(plaintext) == 0:
        # tidak ada blok plaintext sama sekali -> tidak menghasilkan ciphertext
        return b""
    return bytes(ciphertext)


def _process_ciphertext_decrypt(S, ciphertext: bytes) -> bytes:
    """Mendekripsi ciphertext blok-per-blok. Selalu ada minimal satu blok
    'terakhir' (mengikuti aturan padding ASCON), termasuk saat ciphertext
    kosong atau panjangnya tepat kelipatan rate."""
    L = len(ciphertext)
    total_blocks = L // RATE_BYTES + 1  # minimal 1, konsisten dgn skema padding
    plaintext = bytearray()
    idx = 0
    for i in range(total_blocks):
        is_last = (i == total_blocks - 1)
        if not is_last:
            block = ciphertext[idx: idx + RATE_BYTES]
            cblock = _bytes_to_int(block)
            p_block = S[0] ^ cblock
            plaintext += _int_to_bytes(p_block, RATE_BYTES)
            S[0] = cblock
            _permutation(S, ROUNDS_B)
            idx += RATE_BYTES
        else:
            remaining = L - idx  # 0..RATE_BYTES-1 byte ciphertext tersisa
            block = ciphertext[idx: idx + remaining]
            keystream_bytes = _int_to_bytes(S[0], RATE_BYTES)
            p_bytes = bytes(a ^ b for a, b in zip(block, keystream_bytes[:remaining]))
            plaintext += p_bytes
            # rekonstruksi blok plaintext-terpadding lalu XOR-kan ke S[0],
            # identik dengan operasi yang dilakukan pada sisi enkripsi
            padded_block = p_bytes + b"\x80" + bytes(RATE_BYTES - remaining - 1)
            S[0] ^= _bytes_to_int(padded_block)
    return bytes(plaintext)


def _finalize(S, key: bytes) -> bytes:
    S[1] ^= _bytes_to_int(key[0:8])
    S[2] ^= _bytes_to_int(key[8:16])
    _permutation(S, ROUNDS_A)
    S[3] ^= _bytes_to_int(key[0:8])
    S[4] ^= _bytes_to_int(key[8:16])
    return _int_to_bytes(S[3], 8) + _int_to_bytes(S[4], 8)


# ---------------------------------------------------------------------------
# API publik
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """Membangkitkan kunci rahasia 128-bit secara acak (CSPRNG)."""
    return os.urandom(KEY_BYTES)


def generate_nonce() -> bytes:
    """Membangkitkan nonce 128-bit secara acak. Pada praktiknya nonce harus
    unik setiap enkripsi dengan kunci yang sama; skenario benchmark ini
    membangkitkan nonce baru per paket."""
    return os.urandom(NONCE_BYTES)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Mengenkripsi plaintext dengan ASCON-128 AEAD. Mengembalikan
    ciphertext || tag (tag 16 byte di akhir)."""
    assert len(key) == KEY_BYTES, "Kunci ASCON-128 harus 16 byte"
    assert len(nonce) == NONCE_BYTES, "Nonce ASCON-128 harus 16 byte"
    S = _initialize(key, nonce)
    _process_associated_data(S, associated_data)
    ciphertext = _process_plaintext_encrypt(S, plaintext)
    tag = _finalize(S, key)
    return ciphertext + tag


def decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes,
            associated_data: bytes = b""):
    """Memverifikasi tag & mendekripsi. Mengembalikan plaintext (bytes) bila
    tag valid, atau None bila verifikasi gagal (paket ditolak)."""
    assert len(key) == KEY_BYTES, "Kunci ASCON-128 harus 16 byte"
    assert len(nonce) == NONCE_BYTES, "Nonce ASCON-128 harus 16 byte"
    if len(ciphertext_and_tag) < TAG_BYTES:
        return None
    ciphertext = ciphertext_and_tag[:-TAG_BYTES]
    received_tag = ciphertext_and_tag[-TAG_BYTES:]

    S = _initialize(key, nonce)
    _process_associated_data(S, associated_data)
    plaintext = _process_ciphertext_decrypt(S, ciphertext)
    computed_tag = _finalize(S, key)

    # perbandingan waktu-konstan untuk menghindari timing side-channel
    if _constant_time_eq(computed_tag, received_tag):
        return plaintext
    return None


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# Self-test terhadap test vector resmi NIST LWC (Ascon-128 v1.2, count=1)
# ---------------------------------------------------------------------------

def _self_test():
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    nonce = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    pt = b""
    ad = b""
    expected_ct = bytes.fromhex("E355159F292911F794CB1432A0103A8A".lower())
    out = encrypt(key, nonce, pt, ad)
    assert out.hex() == expected_ct.hex(), f"Self-test GAGAL: {out.hex()} != {expected_ct.hex()}"

    # uji roundtrip encrypt/decrypt untuk berbagai ukuran payload
    for size in [0, 1, 7, 8, 9, 16, 63, 64, 65, 256, 1024]:
        k = generate_key()
        n = generate_nonce()
        msg = os.urandom(size)
        ct = encrypt(k, n, msg, b"iot-sensor")
        pt2 = decrypt(k, n, ct, b"iot-sensor")
        assert pt2 == msg, f"Roundtrip gagal pada ukuran {size} byte"

        # tag salah (tampered) harus ditolak
        tampered = bytearray(ct)
        tampered[-1] ^= 0x01
        assert decrypt(k, n, bytes(tampered), b"iot-sensor") is None, \
            f"Deteksi tamper gagal pada ukuran {size} byte"

    print("[crypto_utils] Self-test ASCON-128 AEAD: OK "
          "(test vector NIST LWC cocok, roundtrip & deteksi tamper berhasil)")


if __name__ == "__main__":
    _self_test()
