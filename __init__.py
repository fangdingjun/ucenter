# -*- coding=utf-8 -*-
try:
    from Crypto.Cipher import ARC4
    def rc4(d, k):
        a = ARC4.new(k)
        return a.encrypt(d)
except ImportError:
    def rc4(string, cryptkey):
        key_length = len(cryptkey)
        string_length = len(string)
        result = ''
        rndkey = [ord(cryptkey[i % key_length]) for i in range(256)]
        box = range(256)
        j = 0
        for i in xrange(256):
            j = (j + box[i] + rndkey[i]) % 256
            box[i], box[j] = box[j], box[i]

        a, j = 0, 0
        for i in xrange(string_length):
            a = (a + 1) % 256
            j = (j + box[a]) % 256
            box[a], box[j] = box[j], box[a]
            result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))
        return result

def now():
    import time
    return int(time.time())

def md5(s):
    try:
        from hashlib import md5
    except ImportError:
        from md5 import md5
    return md5(s).hexdigest()   

from ucenter.base import Configs, Ucenter
from ucenter.client import Client
from ucenter.uc_php import UcenterAPI

__all__ = ['Ucenter', 'Configs', 'Client', 'UcenterAPI', 'now', 'md5']
