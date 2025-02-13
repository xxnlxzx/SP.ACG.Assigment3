from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

import sys
import base64


def make_key_pairs(suffix, key_size=2048):
    rsakey_pair = RSA.generate(key_size)

    with open(suffix + "_private.pem", "w") as f:
        f.write(rsakey_pair.exportKey().decode())
        f.close()

    with open(suffix + "_public.pem", "w") as f:
        f.write(rsakey_pair.publickey().exportKey().decode())
        f.close()


if __name__ == "__main__":
    suffix, key_size = sys.argv[1:]
    make_key_pairs(suffix, key_size)
