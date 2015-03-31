# -*- coding=utf-8 -*-

import base64
import random

from ucenter import *

class Configs(object):
    UC_KEY = ''
    UC_API = ''
    UC_CHARSET = 'utf-8'
    UC_IP = ''
    UC_APPID = ''
    UC_PPP = '20'

    UC_CLIENT_VERSION = '1.6.0'
    UC_CLIENT_RELEASE = '20110501'
    
def b64_encode(s):
    return base64.b64encode(s)
    
def b64_decode(s):
    len1 = len(s)
    len2 = len1 % 4
    s1 = s

    # need padding
    if len2 != 0:
        s1 = s + '=' * len2
    return base64.b64decode(s1)

def random_string(length):
    charArray = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    return ''.join([random.choice(charArray) for i in range(length)])

class Ucenter(object):
    ENCODE, DECODE = 0, 1

    @classmethod
    def authcode_encode(cls, string, key, expiry=0):
        return cls.authcode(string, key, cls.ENCODE, expiry)

    @classmethod
    def authcode_decode(cls, string, key, expiry=0):
        return cls.authcode(string, key, cls.DECODE, expiry)

    @classmethod
    def authcode(cls, string, key, operation, expiry=0):
        if not string:
            return ''
        
        ckey_length = 4
        key = md5(key or Configs.UC_KEY)
        keya = md5(key[:16])
        keyb = md5(key[16:])
        if ckey_length:
            if operation == cls.DECODE:
                keyc = string[:ckey_length]
            else:
                keyc = random_string(ckey_length)
        else:
            keyc = ''

        cryptkey = keya + md5(keya + keyc)

        if operation == cls.DECODE:
            string = b64_decode(string[ckey_length:])
        else:
            if expiry:
                expiry += now()
            string = '%10d' % expiry + md5(string + keyb)[:16] + string

        result = rc4(string, cryptkey)
    
        if operation == cls.DECODE:
            if (int(result[:10]) == 0 or int(result[:10]) - now() > 0) \
                and result[10:26] == md5(result[26:] + keyb)[:16]:
                    return result[26:]
            else:
                return ''
        else:
            return keyc + b64_encode(result).replace('=', '')
