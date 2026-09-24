"""Dependency-free ECDSA P-256 / SHA-256 verification (NIST SP 800-186 curve).

Verification only handles public data, so plain Python arithmetic is fine.
`sign` exists for tests with throwaway keys; release keys live in the
Keychain and are only ever used through tools/sign_release.swift.
"""
import hashlib
import secrets

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        m = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (m * m - p[0] - q[0]) % P
    return x, (m * (p[0] - x) - p[1]) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point); k >>= 1
    return result


def public_point(x963):
    """Parse an uncompressed X9.63 key (0x04 || X || Y) and check it is on the curve."""
    if len(x963) != 65 or x963[0] != 4:
        raise ValueError('expected 65-byte uncompressed P-256 public key')
    x, y = int.from_bytes(x963[1:33], 'big'), int.from_bytes(x963[33:], 'big')
    if not (0 <= x < P and 0 <= y < P) or (y * y - x * x * x - A * x - B) % P:
        raise ValueError('public key is not on P-256')
    return x, y


def _der_int(data, offset):
    if data[offset] != 2:
        raise ValueError('bad DER integer')
    length = data[offset + 1]
    if length == 0 or length > 33 or (length > 1 and data[offset + 2] == 0 and data[offset + 3] < 128):
        raise ValueError('non-minimal DER integer')
    if data[offset + 2] & 128:
        raise ValueError('negative DER integer')
    return int.from_bytes(data[offset + 2:offset + 2 + length], 'big'), offset + 2 + length


def decode_der(signature):
    if len(signature) < 8 or signature[0] != 0x30 or signature[1] != len(signature) - 2:
        raise ValueError('bad DER signature')
    r, offset = _der_int(signature, 2)
    s, offset = _der_int(signature, offset)
    if offset != len(signature):
        raise ValueError('trailing DER bytes')
    return r, s


def encode_der(r, s):
    def integer(v):
        raw = v.to_bytes((v.bit_length() + 8) // 8, 'big')
        return b'\x02' + bytes([len(raw)]) + raw
    body = integer(r) + integer(s)
    return b'\x30' + bytes([len(body)]) + body


def verify(x963, message, signature):
    """True only for a valid DER ECDSA-P256-SHA256 signature over message."""
    try:
        q = public_point(x963)
        r, s = decode_der(signature)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    w = pow(s, -1, N)
    point = _add(_mul(e * w % N, G), _mul(r * w % N, q))
    return point is not None and point[0] % N == r


def generate():
    """Throwaway test key pair: (private scalar, X9.63 public key)."""
    d = secrets.randbelow(N - 1) + 1
    x, y = _mul(d, G)
    return d, b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def sign(d, message):
    """Test-only signer (random nonce). Never used for release keys."""
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = _mul(k, G)[0] % N
        s = pow(k, -1, N) * (e + r * d) % N
        if r and s:
            return encode_der(r, min(s, N - s))
