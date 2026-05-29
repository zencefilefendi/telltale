"""
TELLTALE — QUIC Initial Packet Decryption

QUIC encrypts its Initial packets. However, the keys are derived from the
publicly visible Destination Connection ID using a version-specific salt.
By extracting the DCID and deriving the keys, we can decrypt the Initial
packet, extract the CRYPTO frame, and parse the TLS 1.3 ClientHello to
read the SNI (Server Name Indication) and JA3 fingerprint.

This requires the `cryptography` module. If unavailable, it degrades gracefully.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _parse_varint(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    v_len = 1 << (first >> 6)
    val = first & 0x3f
    for i in range(1, v_len):
        val = (val << 8) | data[offset + i]
    return val, offset + v_len


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    label_bytes = b"tls13 " + label.encode("ascii")
    info = length.to_bytes(2, "big") + bytes([len(label_bytes)]) + label_bytes + bytes([len(context)]) + context
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def extract_quic_crypto_frame(data: bytes) -> Optional[bytes]:
    """Decrypts a QUIC Initial packet and extracts the TLS CRYPTO frame."""
    if not HAVE_CRYPTO or len(data) < 1200:
        return None

    first_byte = data[0]
    if (first_byte & 0xc0) != 0xc0:  # Must be Long Header (0x80) + Initial (0x30)
        return None

    version = int.from_bytes(data[1:5], "big")
    if version == 0x00000001:  # QUIC v1
        salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    elif version == 0xff00001d:  # Draft-29
        salt = bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899")
    else:
        return None

    try:
        dcid_len = data[5]
        dcid = data[6:6 + dcid_len]
        offset = 6 + dcid_len

        scid_len = data[offset]
        offset += 1 + scid_len

        # Token
        token_len, offset = _parse_varint(data, offset)
        offset += token_len

        # Length
        length, offset = _parse_varint(data, offset)

        if offset + 4 + 16 > len(data):
            return None

        # Key Derivation
        prk = hmac.new(salt, dcid, hashlib.sha256).digest()
        client_initial_secret = _hkdf_expand_label(prk, "client in", b"", 32)
        key = _hkdf_expand_label(client_initial_secret, "quic key", b"", 16)
        iv = _hkdf_expand_label(client_initial_secret, "quic iv", b"", 12)
        hp = _hkdf_expand_label(client_initial_secret, "quic hp", b"", 16)

        sample_offset = offset + 4
        sample = data[sample_offset : sample_offset + 16]

        # Header Protection Removal
        cipher = Cipher(algorithms.AES(hp), modes.ECB())
        encryptor = cipher.encryptor()
        mask = encryptor.update(sample)

        unmasked_first_byte = first_byte ^ (mask[0] & 0x0f)
        pn_len = (unmasked_first_byte & 0x03) + 1

        pn_bytes = bytearray(data[offset : offset + pn_len])
        for i in range(pn_len):
            pn_bytes[i] ^= mask[i + 1]

        # AAD
        aad = bytearray(data[:offset])
        aad[0] = unmasked_first_byte
        aad.extend(pn_bytes)

        # Nonce
        nonce = bytearray(iv)
        for i in range(pn_len):
            nonce[11 - i] ^= pn_bytes[pn_len - 1 - i]

        payload_offset = offset + pn_len
        payload_length = length - pn_len

        encrypted_payload = data[payload_offset : payload_offset + payload_length]

        # Decrypt payload
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, encrypted_payload, bytes(aad))

        # Extract CRYPTO frame
        idx = 0
        while idx < len(plaintext):
            frame_type = plaintext[idx]
            idx += 1
            if frame_type == 0x00:  # PADDING
                continue
            elif frame_type == 0x01:  # PING
                continue
            elif frame_type == 0x06:  # CRYPTO
                crypto_offset, idx = _parse_varint(plaintext, idx)
                crypto_length, idx = _parse_varint(plaintext, idx)
                return plaintext[idx : idx + crypto_length]
            else:
                # To be robust we'd need to parse all frames, but CRYPTO is usually first/early.
                break

        return None
    except Exception:
        return None
