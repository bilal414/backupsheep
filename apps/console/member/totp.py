"""Small RFC 6238 implementation used for local authenticator-app MFA.

Keeping this primitive local avoids making login availability depend on a third-party
verification API. Secrets are generated with the operating system CSPRNG and encrypted
by the member model before they are stored.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode


TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_secret(secret):
    value = str(secret or "").strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(value) % 8) % 8)
    return base64.b32decode(value + padding, casefold=True)


def totp_for_counter(secret, counter, digits=TOTP_DIGITS):
    key = _decode_secret(secret)
    message = struct.pack(">Q", int(counter))
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def matching_totp_counter(secret, token, *, at_time=None, window=1):
    token = str(token or "").strip().replace(" ", "")
    if len(token) != TOTP_DIGITS or not token.isdigit():
        return None
    now = time.time() if at_time is None else float(at_time)
    current = int(now // TOTP_PERIOD_SECONDS)
    # Prefer the newest valid counter if clock-skew windows overlap around a boundary.
    for counter in range(current + int(window), current - int(window) - 1, -1):
        if counter >= 0 and secrets.compare_digest(
            totp_for_counter(secret, counter), token
        ):
            return counter
    return None


def provisioning_uri(secret, email, *, issuer="BackupSheep"):
    label = f"{issuer}:{email}"
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD_SECONDS,
        }
    )
    return f"otpauth://totp/{quote(label, safe='')}?{query}"
