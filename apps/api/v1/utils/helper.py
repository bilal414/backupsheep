from random import choice
from string import ascii_lowercase, digits
import re
from cryptography.fernet import Fernet
from sentry_sdk import capture_exception


def random_code(
        model,
        field="code",
        length=16,
        chars=ascii_lowercase + digits,
        split=4,
        delimiter="-",
):
    code = "".join([choice(chars) for i in range(length)])

    if split:
        code = delimiter.join(
            [code[start: start + split] for start in range(0, len(code), split)]
        )
    try:
        model.objects.get(**{field: code})
        return random_code(
            model,
            field=field,
            length=length,
            chars=chars,
            split=split,
            delimiter=delimiter,
        )
    except model.DoesNotExist:
        return code


def clean_phone_number(phone_number):
    return re.sub(r"[ \-\(\)]", "", phone_number)


def bs_encrypt(plaintext, key):
    if plaintext:
        if plaintext.strip() != "":
            try:
                f = Fernet(key)
                return f.encrypt(plaintext.encode("utf-8"))
            except Exception as e:
                capture_exception(e)
        else:
            return None
    else:
        return None


def bs_decrypt(ciphertext, key):
    if ciphertext:
        try:
            f = Fernet(key)
            return f.decrypt(bytes(ciphertext)).decode("utf-8")
        except Exception as e:
            capture_exception(e)
    else:
        return None
