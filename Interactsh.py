#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Author  : RedTeamWing
# @CreateTime: 2021/11/6 下午4:08
# @FileName: Interactsh.py
# @Blog：https://redteamwing.com
import base64
import json
import codecs
import random

import Crypto
import rsa
import requests
from uuid import uuid4

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from xid import XID
from base64 import b64encode
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher, PKCS1_OAEP

guid = XID()


class Interactsh:
    def __init__(self):
        random_generator = Random.new().read
        rsa = RSA.generate(2048, random_generator)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.headers = {
            "Content-Type": "application/json"
        }
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        self.correlation_id = guid.string()

        print(self.secret)
        print(self.correlation_id)
        self.Register()

    def Register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        try:
            resp = requests.post("https://interactsh.com/register", headers=self.headers, data=json.dumps(data))
        except Exception as e:
            print(e)
            return "error"

    def Poll(self):
        try:
            result = []
            protocol_list = []
            url = f"https://interactsh.com/poll?id={self.correlation_id}&secret={self.secret}"
            resp2 = requests.get(url)
            reps2 = json.loads(resp2.text)
            aes_key = reps2["aes_key"]
            data_list = reps2["data"]
            if data_list:
                for i in data_list:
                    protocol, decrypt_data = self.DecryptData(aes_key, i)
                    result.append(decrypt_data)
                    protocol_list.append(protocol)
            return protocol_list, result
        except Exception as e:
            print(e)
            return ""

    def DecryptData(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        protocol = json.loads(plain_text[16:])["protocol"]
        return protocol, plain_text[16:]

    def GetDomain(self):
        domain = self.correlation_id
        while (len(domain) < 33):
            domain += chr(ord('a') + random.randint(1, 24))
        domain += ".interactsh.com"
        return domain
