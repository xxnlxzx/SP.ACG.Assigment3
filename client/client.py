# ------------------------------------------------------------------------------------------
# Client.py
# ------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client

import datetime
import sys  # handle system error
import socket
import time
import hmac
import hashlib

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from keys import get_hmac_key

global host, port

host = socket.gethostname()
port = 8888  # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"
sha1_hash_size = 20
rsa_signature_size = 256
server_key_file = "server_public.pem"
aes_key_length = 16
block_size = 16

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU)

    hmac_key = get_hmac_key()
    with open(menu_file, "wb") as menu_file_writer:
        while True:
            read_data = my_socket.recv(4096)

            if read_data == b"":
                break

            # get hash
            read_hash = read_data[-sha1_hash_size:]
            # get message block
            read_data_block = read_data[: len(read_data) - sha1_hash_size]

            # get signer
            signer = hmac.new(hmac_key, read_data_block, hashlib.sha1)

            # verify hash by comparing the bytes of the hash from the message against the your generated hash
            if read_hash != signer.digest():
                raise Exception("Menu data integrity compromised, exiting")

            menu_file_writer.write(read_data_block)
        menu_file_writer.close()
    # hints : need to apply a scheme to verify the integrity of data.
    # menu_file = open(menu_file, "wb")
    # menu_file.write(data)
    # menu_file.close()
    my_socket.close()
print("Menu today received from server")
# print('Received', repr(data))  # for debugging use
my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
        out_file = open(return_file, "rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    # file_bytes = out_file.read(1024 - rsa_signature_size)
    file_bytes = out_file.read(1024)

    # import server public key
    with open(server_key_file, "r") as f:
        server_public_key = RSA.importKey(f.read())
        cipher = PKCS1_OAEP.new(server_public_key)
        aes_secret = get_random_bytes(aes_key_length)
        iv = get_random_bytes(aes_key_length)
        aes_iv = aes_secret + iv

        encrypted_aes_key = cipher.encrypt(aes_iv)
        my_socket.send(encrypted_aes_key)

        # create aes key to encrypt subsequent bytes
        aes_cipher = AES.new(aes_secret, AES.MODE_CBC, iv)

    sent_bytes = b""
    while file_bytes != b"":
        # hints: need to protect the file_bytes in a way before sending out.
        cipher_bytes = aes_cipher.encrypt(pad(file_bytes, block_size))

        # digitally sign the block of data before sending out

        # my_socket.send(file_bytes)
        my_socket.send(cipher_bytes)
        print("length of data", len(file_bytes))
        print("length of cipher bytes", len(cipher_bytes))
        sent_bytes += file_bytes

        file_bytes = out_file.read(1024)

        # file_bytes = out_file.read(
        #     1024 - rsa_signature_size
        # )  # read next block from file
    out_file.close()
    my_socket.close()
print("Sale of the day sent to server")
# print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
