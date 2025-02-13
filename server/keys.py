hmac_key_path = "secrets/message.key"


def get_hmac_key():
    with open(hmac_key_path, "rb") as f:
        key_bytes = f.read()
        return key_bytes
