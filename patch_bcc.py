import re

with open('rust/cbor-cose/src/bcc.rs', 'r') as f:
    content = f.read()

content = content.replace('fn public_key_to_cose_key', 'pub fn public_key_to_cose_key')

with open('rust/cbor-cose/src/bcc.rs', 'w') as f:
    f.write(content)
