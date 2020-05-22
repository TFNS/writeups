class OTS:
    def __init__(self):
        self.key_len = 128
        self.priv_key = secrets.token_bytes(16*self.key_len)
        self.pub_key = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255) for i in range(self.key_len)]).hex()

    def hash_iter(self, msg, n):
        assert len(msg) == 16
        for i in range(n):
            msg = hashlib.md5(msg).digest()
        return msg

    def wrap(self, msg):
        raw = msg.encode('utf-8')
        assert len(raw) <= self.key_len - 16
        raw = raw + b'\x00'*(self.key_len - 16 - len(raw))
        raw = raw + hashlib.md5(raw).digest()
        return raw

    def sign(self, msg):
        raw = self.wrap(msg)
        signature = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255-raw[i]) for i in range(len(raw))]).hex()
        self.verify(msg, signature)
        return signature

    def verify(self, msg, signature):
        raw = self.wrap(msg)
        signature = bytes.fromhex(signature)
        assert len(signature) == self.key_len * 16
        calc_pub_key = b''.join([self.hash_iter(signature[16*i:16*(i+1)], raw[i]) for i in range(len(raw))]).hex()
        assert hmac.compare_digest(self.pub_key, calc_pub_key)