"""
attacker.py
============
Simulasi paket termanipulasi (kondisi tampered) untuk menguji ketahanan
mekanisme verifikasi tag autentikasi ASCON-128 AEAD.

Empat varian manipulasi (Tabel 4, skenario S4):
  1. bit_flip_ciphertext  -> pembalikan satu bit pada bagian ciphertext
  2. random_tag           -> penggantian authentication tag dengan nilai acak
  3. wrong_nonce          -> perubahan nilai nonce (tidak sesuai saat enkripsi)
  4. wrong_key            -> penggunaan kunci rahasia berbeda pada pengirim
"""

import os
import random
from dataclasses import dataclass

import crypto_utils

TAG_BYTES = 16

ATTACK_VARIANTS = [
    "bit_flip_ciphertext",
    "random_tag",
    "wrong_nonce",
    "wrong_key",
]


@dataclass
class TamperedPacket:
    variant: str
    key: bytes          # kunci yang dipakai pengirim utk mengklaim paket ini
    nonce: bytes         # nonce yang disertakan dalam paket
    ciphertext_and_tag: bytes
    description: str


def bit_flip_ciphertext(key: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> TamperedPacket:
    """Membalik satu bit acak pada bagian ciphertext (bukan pada tag)."""
    ct_len = len(ciphertext_and_tag) - TAG_BYTES
    tampered = bytearray(ciphertext_and_tag)
    if ct_len > 0:
        byte_idx = random.randrange(0, ct_len)
        bit_idx = random.randrange(0, 8)
        tampered[byte_idx] ^= (1 << bit_idx)
    else:
        # tidak ada ciphertext (payload kosong) -> balik bit pada tag sebagai gantinya
        tampered[0] ^= 0x01
    return TamperedPacket(
        variant="bit_flip_ciphertext",
        key=key, nonce=nonce,
        ciphertext_and_tag=bytes(tampered),
        description="Satu bit pada ciphertext dibalik untuk menguji sensitivitas tag",
    )


def random_tag(key: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> TamperedPacket:
    """Mengganti authentication tag (16 byte terakhir) dengan nilai acak."""
    ct = ciphertext_and_tag[:-TAG_BYTES]
    fake_tag = os.urandom(TAG_BYTES)
    return TamperedPacket(
        variant="random_tag",
        key=key, nonce=nonce,
        ciphertext_and_tag=ct + fake_tag,
        description="Authentication tag diganti nilai acak untuk menguji penolakan tag tidak sah",
    )


def wrong_nonce(key: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> TamperedPacket:
    """Mengirim paket dengan nonce yang berbeda dari nonce saat enkripsi."""
    fake_nonce = os.urandom(len(nonce))
    return TamperedPacket(
        variant="wrong_nonce",
        key=key, nonce=fake_nonce,
        ciphertext_and_tag=ciphertext_and_tag,
        description="Nonce diubah sehingga tidak sesuai nonce saat proses enkripsi",
    )


def wrong_key(key: bytes, nonce: bytes, ciphertext_and_tag: bytes,
              plaintext: bytes = None, associated_data: bytes = b"") -> TamperedPacket:
    """Mengirim paket seolah dienkripsi dengan kunci rahasia berbeda.

    Catatan penting: kunci rahasia TIDAK pernah ikut ditransmisikan pada
    paket (hanya nonce dan ciphertext||tag yang dikirim melalui jalur
    komunikasi), sehingga simulasi 'kunci pengirim berbeda' harus benar-benar
    meng-enkripsi ulang plaintext memakai kunci palsu -- bukan sekadar
    mengganti label kunci pada objek tampered -- agar ciphertext yang
    dikirim benar-benar berubah dan penerima (yang memakai kunci asli)
    gagal memverifikasinya.
    """
    fake_key = os.urandom(len(key))
    if plaintext is not None:
        fake_ct_and_tag = crypto_utils.encrypt(fake_key, nonce, plaintext, associated_data)
    else:
        # fallback jika plaintext tidak tersedia: acak-kan ciphertext & tag
        fake_ct_and_tag = os.urandom(len(ciphertext_and_tag))
    return TamperedPacket(
        variant="wrong_key",
        key=fake_key, nonce=nonce,
        ciphertext_and_tag=fake_ct_and_tag,
        description="Pengirim mengenkripsi ulang dengan kunci rahasia berbeda, "
                    "menguji kegagalan autentikasi akibat ketidaksesuaian kunci",
    )


_VARIANT_FUNCS = {
    "bit_flip_ciphertext": bit_flip_ciphertext,
    "random_tag": random_tag,
    "wrong_nonce": wrong_nonce,
    "wrong_key": wrong_key,
}


def generate_tampered_packet(key: bytes, nonce: bytes, ciphertext_and_tag: bytes,
                              variant: str = None, plaintext: bytes = None,
                              associated_data: bytes = b"") -> TamperedPacket:
    """Menghasilkan satu paket tampered. Jika variant tidak ditentukan,
    dipilih secara acak dari ATTACK_VARIANTS. `plaintext` & `associated_data`
    hanya dipakai oleh varian wrong_key (perlu re-enkripsi dengan kunci palsu)."""
    variant = variant or random.choice(ATTACK_VARIANTS)
    func = _VARIANT_FUNCS[variant]
    if variant == "wrong_key":
        return func(key, nonce, ciphertext_and_tag, plaintext=plaintext,
                    associated_data=associated_data)
    return func(key, nonce, ciphertext_and_tag)
