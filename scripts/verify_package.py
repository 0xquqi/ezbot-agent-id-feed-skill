#!/usr/bin/env python3
"""Verify a local audit/package ZIP with an independently trusted key fingerprint."""
import argparse,hashlib,json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',type=Path);p.add_argument('signature',type=Path);p.add_argument('--public-key',required=True);a=p.parse_args()
d=json.loads(a.signature.read_text());h=hashlib.sha256(a.archive.read_bytes()).hexdigest()
if d.get('algorithm')!='Ed25519' or d.get('domain')!='EZBOT-FEED-PACKAGE-V1' or d.get('sha256')!=h:raise SystemExit('invalid_package_signature')
Ed25519PublicKey.from_public_bytes(bytes.fromhex(a.public_key)).verify(bytes.fromhex(d['signature']),('EZBOT-FEED-PACKAGE-V1\n'+h).encode())
print('Package signature verified; confirm this public key via an independent trusted channel.')
