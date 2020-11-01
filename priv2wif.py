#!/usr/bin/env python3
import hashlib as hl
import base58 as bs

priv = bytes.fromhex('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D')

suffix = hl.sha256(hl.sha256(b'\x80' + priv).digest()).digest()[:4]

print(bs.b58encode(b'\x80' + priv + suffix))
print(bs.b58encode_check(b'\x80' + priv))
