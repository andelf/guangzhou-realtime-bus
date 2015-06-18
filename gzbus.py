#!/usr/bin/python
# -*- coding: utf-8 -*-
# #  FileName    : gzbus.py
# #  Author      : ShuYu Wang <andelf@gmail.com>
# #  Created     : Fri Jun 19 01:10:19 2015 by ShuYu Wang
# #  Copyright   : Feather Workshop (c) 2015
# #  Description : description
# #  Time-stamp: <2015-06-19 01:10:22 andelf>

from Crypto.Cipher import DES
from Crypto.PublicKey import RSA

import struct
import urllib
import urllib2
import hashlib

md5 = lambda n: hashlib.md5(n).digest()


class GuangzhouBus(object):
    def __init__(self):
        cp = urllib2.HTTPCookieProcessor()
        self.opener = urllib2.build_opener(cp)

        self.init_trans_table()

        self.init_crypto()

    def init_trans_table(self):
        encrypt_table = [232, 233, 234, 235, 236, 237, 238, 239, 224, 225, 226, 227, 228, 229, 230, 231, 248, 249, 250,
                         251, 252, 253, 254, 255, 240, 241, 242, 243, 244, 245, 246, 247, 8, 9, 10, 11, 12, 13, 14, 15,
                         0, 1, 2, 3, 4, 5, 6, 7, 24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 40, 41,
                         42, 43, 44, 45, 46, 47, 32, 33, 34, 35, 36, 37, 38, 39, 56, 57, 58, 59, 60, 61, 62, 63, 48, 49,
                         50, 51, 52, 53, 54, 55, 72, 73, 74, 75, 76, 77, 78, 79, 64, 65, 66, 67, 68, 69, 70, 71, 88, 89,
                         90, 91, 92, 93, 94, 95, 80, 81, 82, 83, 84, 85, 86, 87, 104, 105, 106, 107, 108, 109, 110, 111,
                         96, 97, 98, 99, 100, 101, 102, 103, 120, 121, 122, 123, 124, 125, 126, 127, 112, 113, 114, 115,
                         116, 117, 118, 119, 136, 137, 138, 139, 140, 141, 142, 143, 128, 129, 130, 131, 132, 133, 134,
                         135, 152, 153, 154, 155, 156, 157, 158, 159, 144, 145, 146, 147, 148, 149, 150, 151, 168, 169,
                         170, 171, 172, 173, 174, 175, 160, 161, 162, 163, 164, 165, 166, 167, 184, 185, 186, 187, 188,
                         189, 190, 191, 176, 177, 178, 179, 180, 181, 182, 183, 200, 201, 202, 203, 204, 205, 206, 207,
                         192, 193, 194, 195, 196, 197, 198, 199, 216, 217, 218, 219, 220, 221, 222, 223, 208, 209, 210,
                         211, 212, 213, 214, 215]

        decrypt_table = [0] * 256

        idx = 0
        while idx < (0x80 << 0x1):
            val = encrypt_table[idx]
            decrypt_table[val] = idx
            idx += 1

        self.encrypt_table = encrypt_table
        self.decrypt_table = decrypt_table


    def trans_decrypt(self, s):
        return ''.join(chr(self.decrypt_table[ord(c)]) for c in s)

    def trans_encrypt(self, s):
        return ''.join(chr(self.encrypt_table[ord(c)]) for c in s)

    def wrap_payload(self, raw):
        prefix = struct.pack("<I", len(raw))
        checksum = md5(raw)

        return ''.join([
            struct.pack("<I", len(raw)),
            raw,
            struct.pack("<I", 0x10), # length of md5 digest,
            checksum])

    def init_crypto(self):
        self.rsa = rsa = RSA.generate(1024, e=3)

        pubkey = rsa.publickey().exportKey("DER")[22:]
        encrypted_pubkey = self.trans_encrypt(pubkey)
        payload = self.wrap_payload(encrypted_pubkey)

        req = urllib2.Request("http://info.gzyyjt.net:9009/guangzhou/key", payload.encode('base64'),
                              headers={"Content-Type": "text/plain",
                                       'User-Agent': "Apache-HttpClient/UNAVAILABLE (java 1.4)"})
        resp = self.opener.open(req)

        raw = resp.read()

        payload = rsa.decrypt(raw.decode('base64'))

        self.des_key = des_key = payload[99:107]
        # MD5 checksum
        assert md5(des_key) == payload[-16:]

        print repr(payload)


    def des_encrypt(self, text):
        key = self.trans_encrypt(key)
        IV = '\0' * 8
        des = DES.new(self.des_key, DES.MODE_OFB, IV)
        payload = des.encrypt(text)
        return payload

    def des_decrypt(self, cipher):
        key = self.trans_encrypt(key)
        IV = '\0' * 8
        des = DES.new(self.des_key, DES.MODE_OFB, IV)
        payload = des.decrypt(cipher)
        return payload





api = GuangzhouBus()
