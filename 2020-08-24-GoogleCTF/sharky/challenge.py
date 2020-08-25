#! /usr/bin/python3
import binascii
import os
import sha256

# Setup msg_secret and flag
FLAG_PATH = 'data/flag.txt'
NUM_KEYS = 8
MSG = b'Encoded with random keys'

with open(FLAG_PATH, 'rb') as f:
  FLAG = f.read().strip().decode('utf-8')


def sha256_with_secret_round_keys(m: bytes, secret_round_keys: dict) -> bytes:
  """Computes SHA256 with some secret round keys.

  Args:
    m: the message to hash
    secret_round_keys: a dictionary where secret_round_keys[i] is the value of
      the round key k[i] used in SHA-256

  Returns:
    the digest
  """
  sha = sha256.SHA256()
  round_keys = sha.k[:]
  for i, v in secret_round_keys.items():
    round_keys[i] = v
  return sha.sha256(m, round_keys)


def generate_random_round_keys(cnt: int):
  res = {}
  for i in range(cnt):
    rk = 0
    for b in os.urandom(4):
      rk = rk * 256 + b
    res[i] = rk
  return res

if __name__ == '__main__':
  secret_round_keys = generate_random_round_keys(NUM_KEYS)
  digest = sha256_with_secret_round_keys(MSG, secret_round_keys)
  print('MSG Digest: {}'.format(binascii.hexlify(digest).decode()))
  GIVEN_KEYS = list(map(lambda s: int(s, 16), input('Enter keys: ').split(',')))
  assert len(GIVEN_KEYS) == NUM_KEYS, 'Wrong number of keys provided.'

  if all([GIVEN_KEYS[i] == secret_round_keys[i] for i in range(NUM_KEYS)]):
    print('\nGood job, here\'s a flag: {0}'.format(FLAG))
  else:
    print('\nSorry, that\'s not right.')
