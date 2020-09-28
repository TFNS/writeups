#!/usr/bin/env python3
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify
from base64 import b64encode, b64decode
from cmd import Cmd
import binascii
import shlex
import os
BLOCK_SIZE = 16  # Bytes
CTR_SIZE = 4  # Bytes
SECRET = get_random_bytes(BLOCK_SIZE)
exec_whitelist = ['exit', 'echo', 'ls']
cmd_whitelist = ['help', '?', 'quit', 'sign_command']
class CryptoShell(Cmd):
    def __init__(self):
        self.cipher = AESCipher( SECRET  )
        super().__init__(None)
    def precmd(self, line):
        if line.split()[0] in cmd_whitelist:
            return line
        try:
            line = self.cipher.decrypt( line )
            return line
        except (binascii.Error, UnicodeDecodeError, ValueError) as e:
            print(e)
            return 'Error'
    def do_echo(self, args):
        print( args )
    def do_sign_command(self, args):
        """ Create a signature for a selected whitelist of allowed commands (for testing purposes)"""
        data = args.split(' ', 1)
        cmd = data[0]
        args = data[1] if 1 < len(data) else ''
        if cmd in exec_whitelist:
            line = 'exec {} {}'.format(cmd, shlex.quote(args))
            print(self.cipher.encrypt(line).decode())
    def do_exec(self, args):
        """ Execute a subcommand"""
        print(args)
        os.system( args  )
    def do_quit(self, args):
        """Quits the program."""
        print("Quitting.")
        raise SystemExit
class AESCipher:
    def __init__(self, key):
        self.key = key
    def encrypt(self, raw):
        iv=get_random_bytes(BLOCK_SIZE)
        raw = pad(raw.encode(), BLOCK_SIZE)
        c_mac = AES.new(self.key, AES.MODE_CBC, iv)
        mac = c_mac.encrypt(raw)[-BLOCK_SIZE:]
        c_enc = AES.new(self.key, AES.MODE_CTR, nonce=iv[:-CTR_SIZE])
        data = c_enc.encrypt(raw)
        return b64encode(iv + data + mac )
    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:BLOCK_SIZE]
        mac = enc[-BLOCK_SIZE:]
        data = enc[BLOCK_SIZE:-BLOCK_SIZE]
        c_enc = AES.new(self.key, AES.MODE_CTR, nonce=iv[:-CTR_SIZE])
        message = c_enc.decrypt(data)
        c_mac = AES.new(self.key, AES.MODE_CBC, iv)
        mac_check = c_mac.encrypt( message )[-BLOCK_SIZE:]
        if mac != mac_check:
            return "Mac Error!"
        else:
            return unpad(message, BLOCK_SIZE).decode('utf8', 'backslashreplace')
if __name__ == "__main__":
    cs = CryptoShell()
    cs.prompt = '> '
    cs.cmdloop('CryptoShell v 0.0.1')
