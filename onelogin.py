#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import hmac
import base64
import struct
import hashlib
import time
import ConfigParser
import os.path
import math
import pyperclip

# import alfred

_MAX_RESULTS = 20
_CONFIG_FILE = os.path.expanduser("~") + '/.gauth'
_CONFIG_FILE_INITIAL_CONTENT = \
    """#Examples of valid configurations:
[onelogin]
secret=xxxxxxxxxxxxxxxxxx
password=xxxxxx
[user.last@somedomain.com]
secret=xxxxxxxxxxxxxxxxxx
"""


def get_hotp_token(key, intervals_no):
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(h[19]) & 15
    h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(key):
    return get_hotp_token(key, intervals_no=int(time.time()) // 30)


def get_section_token(config, section):
    try:
        secret = config.get(section, 'secret')
    except:
        secret = None

    try:
        key = config.get(section, 'key')
    except:
        key = None

    try:
        hexkey = config.get(section, 'hexkey')
    except:
        hexkey = None

    try:
        password = config.get(section, 'password')
    except:
        password = ""

    if hexkey:
        key = hexkey.decode('hex')

    if secret:
        secret = secret.replace(' ', '')
        secret = secret.ljust(int(math.ceil(len(secret) / 16.0) * 16), '=')
        key = base64.b32decode(secret, casefold=True)

    return password + str(get_totp_token(key)).zfill(6)


def get_time_remaining():
    return int(30 - (time.time() % 30))


def is_secret_valid(secret):
    try:
        secret = secret.replace(' ', '')
        secret = secret.ljust(int(math.ceil(len(secret) / 16.0) * 16), '=')
        key = base64.b32decode(secret, casefold=True)
        get_totp_token(key)
    except:
        return False

    return True

def copy_token(config, section):
    token = get_section_token(config, section)
    pyperclip.copy(token)
    # pyperclip.paste()
    print token


def get_config():
    config = ConfigParser.RawConfigParser()
    config.read(os.path.expanduser(_CONFIG_FILE))
    return config


def create_config():
    with open(_CONFIG_FILE, 'w') as f:
        f.write(_CONFIG_FILE_INITIAL_CONTENT)
        f.close()


def is_command(query):
    try:
        command, rest = query.split(' ', 1)
    except ValueError:
        command = query
    command = command.strip()
    return command == 'add' or command == 'update' or command == 'remove'


def main(action, query):
    # If the configuration file doesn't exist, create an empty one
    if not os.path.isfile(_CONFIG_FILE):
        create_config()
        return

    try:
        config = get_config()
        if not config.sections() and action != 'add':
            # If the configuration file is empty, tell the user to add secrets to it
            return
    except Exception as e:
        sys.exit(1)

    if action == 'list' and not is_command(query):
        list_accounts(config, query)
    elif action == 'add':
        add_account(config, query)
    else:
        copy_token(config, query)



if __name__ == "__main__":
    main(action="get", query="onelogin")
