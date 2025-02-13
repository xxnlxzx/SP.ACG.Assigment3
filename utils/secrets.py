from Crypto.Random import get_random_bytes
import sys
import base64


def make_secret_file(filepath, key_size):
    with open(filepath, "w") as f:
        secret = get_random_bytes(key_size)
        f.write(base64.b64encode(secret).decode())
        f.close()


if __name__ == "__main__":
    filepath, key_size = sys.argv[1:]
    print(filepath, key_size)
    make_secret_file(filepath, int(key_size))
