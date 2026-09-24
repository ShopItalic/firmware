#!/usr/bin/env python3
"""Compact device-facing index for products whose firmware updates itself.

Glyph (P13+) downloads `products/glyph/device-v1.json`, not the full catalog:
the device parses with cJSON on a small heap. The index contains only offerable
entries (installable, not withdrawn, with a signed sourceVersions grant and an
MD5 for the factory card), newest first, capped at the device's 8 KiB limit.
Each entry keeps the exact signed statement and signature, so the device
verifies it exactly as clients verify the catalog. `--check` fails if the
committed index differs from the catalog (run in CI).
"""
import argparse
import json
import sys

import catalog

DEVICE_PRODUCTS = {'glyph': 8192}


def path(product):
    return catalog.ROOT / 'products' / product / 'device-v1.json'


def build(product, current):
    limit = DEVICE_PRODUCTS[product]
    keys = catalog.load_keys()
    index = {'schemaVersion': 1, 'product': product, 'hardware': catalog.PRODUCTS[product]['hardware'], 'releases': []}
    for entry in current['releases']:
        s = catalog.verify_entry(product, entry, keys)
        if entry['withdrawn'] or not s['installable'] or 'sourceVersions' not in s or 'md5' not in entry['asset']:
            continue
        candidate = {'statement': entry['statement'], 'signature': entry['signature']['der'],
                     'keyId': entry['signature']['keyId'], 'md5': entry['asset']['md5'], 'withdrawn': False}
        trial = {**index, 'releases': index['releases'] + [candidate]}
        if len(encode(trial)) > limit:
            break  # older offers drop off; the newest always fit first
        index = trial
    return index


def encode(index):
    return json.dumps(index, separators=(',', ':'), ensure_ascii=True).encode()


def write(product, current):
    """Rewrite the device index for products that have one; return written paths."""
    if product not in DEVICE_PRODUCTS:
        return []
    path(product).write_bytes(encode(build(product, current)) + b'\n')
    return [path(product)]


def check(product):
    expected = encode(build(product, catalog.read(product))) + b'\n'
    catalog.require(path(product).exists() and path(product).read_bytes() == expected,
                    f'{path(product).relative_to(catalog.ROOT)} is stale; run tools/device_index.py')
    catalog.require(len(expected) - 1 <= DEVICE_PRODUCTS[product], 'device index exceeds device limit')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for product in DEVICE_PRODUCTS:
        if args.check:
            check(product); print(f'{product}: device index current')
        else:
            write(product, catalog.read(product)); print(f'{product}: device index written')
    sys.exit(0)
