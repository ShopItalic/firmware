"""Catalog schema, signed release statements and validation.

Trust model: GitHub, TLS and this repository only decide *availability*.
Every release carries a statement (exact JSON bytes) signed by the product's
release key. Clients verify the signature over those bytes, parse them, and
trust only what the statement says. Unsigned entry fields are display
metadata; the one unsigned field clients honour is `withdrawn: true`, because
it can only remove an offer.
"""
import base64
import json
import re
from pathlib import Path

import p256

ROOT = Path(__file__).resolve().parents[1]
OWNER_REPO = 'ShopItalic/firmware'
DOWNLOAD = f'https://github.com/{OWNER_REPO}/releases/download/'
ASSET_API = f'https://api.github.com/repos/{OWNER_REPO}/releases/assets/'
SCHEMA = 'italic-firmware-release/1'
CHANNELS = ('test', 'beta', 'stable')
# Product -> hardware and key IDs accepted in its catalog.
PRODUCTS = {
    'glyph': {'hardware': 'PKS3-101', 'keys': ('glyph-release-1',)},
    'sudo': {'hardware': '603V1.23.2', 'keys': ('sudo-release-1',)},
}
SHA = re.compile(r'[0-9a-f]{64}')
RELEASE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+-]{0,47}')
ASSET_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}')
STATEMENT_KEYS = {'schema', 'product', 'hardware', 'id', 'version', 'packageRevision', 'channel',
                  'installable', 'asset', 'sourceVersions', 'issuedAt'}


class CatalogError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CatalogError(message)


def catalog_path(product):
    return ROOT / 'products' / product / 'catalog-v1.json'


def key_path(key_id):
    return ROOT / 'keys' / f'{key_id}.x963'


def tag(product, release_id):
    return f'{product}-{release_id}'


def encode_statement(statement):
    """Canonical bytes to sign. Verifiers use the stored bytes, never re-encode."""
    return json.dumps(statement, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def make_statement(product, release_id, version, revision, channel, installable, asset,
                   issued_at, source_versions=None):
    statement = {'schema': SCHEMA, 'product': product, 'hardware': PRODUCTS[product]['hardware'],
                 'id': release_id, 'version': version, 'packageRevision': revision,
                 'channel': channel, 'installable': installable,
                 'asset': {'name': asset['name'], 'bytes': asset['bytes'], 'sha256': asset['sha256']},
                 'issuedAt': issued_at}
    if source_versions is not None:
        statement['sourceVersions'] = list(source_versions)
    check_statement(statement, product)
    return statement


def check_statement(s, product):
    require(isinstance(s, dict) and set(s) <= STATEMENT_KEYS, 'unexpected statement fields')
    require(s.get('schema') == SCHEMA, 'wrong statement schema')
    require(s.get('product') == product and s.get('hardware') == PRODUCTS[product]['hardware'],
            'statement product/hardware mismatch')
    require(isinstance(s.get('id'), str) and RELEASE_ID.fullmatch(s['id']), 'bad release id')
    require(isinstance(s.get('version'), str) and 0 < len(s['version']) <= 32, 'bad version')
    require(type(s.get('packageRevision')) is int and 1 <= s['packageRevision'] <= 999, 'bad packageRevision')
    require(s.get('channel') in CHANNELS, 'bad channel')
    require(type(s.get('installable')) is bool, 'installable must be boolean')
    a = s.get('asset')
    require(isinstance(a, dict) and set(a) == {'name', 'bytes', 'sha256'}, 'bad statement asset')
    require(isinstance(a['name'], str) and ASSET_NAME.fullmatch(a['name']), 'bad asset name')
    require(type(a['bytes']) is int and 0 < a['bytes'] <= 64 * 1024 * 1024, 'bad asset size')
    require(isinstance(a['sha256'], str) and SHA.fullmatch(a['sha256']), 'bad asset sha256')
    require(isinstance(s.get('issuedAt'), str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', s['issuedAt']),
            'issuedAt must be UTC seconds, e.g. 2026-09-24T12:00:00Z')
    if 'sourceVersions' in s:
        v = s['sourceVersions']
        require(isinstance(v, list) and 0 < len(v) <= 100 and len(set(v)) == len(v)
                and all(isinstance(x, str) and 0 < len(x) <= 32 for x in v), 'bad sourceVersions')


def signed_entry(statement_bytes, key_id, der, url, api_url=None, display=None, details=None, extra_assets=()):
    s = json.loads(statement_bytes)
    entry = {
        'id': s['id'], 'version': s['version'], 'packageRevision': s['packageRevision'],
        'hardware': s['hardware'], 'channel': s['channel'], 'installable': s['installable'],
        'withdrawn': False, 'tag': tag(s['product'], s['id']),
        'asset': {**s['asset'], 'url': url, **({'apiURL': api_url} if api_url else {})},
        'extraAssets': sorted(extra_assets),
        **(display or {}),
        'details': details or {},
        'statement': base64.b64encode(statement_bytes).decode(),
        'signature': {'alg': 'ES256', 'keyId': key_id, 'der': base64.b64encode(der).decode()},
    }
    return entry


def verify_entry(product, entry, keys):
    """Verify one entry; return its parsed statement."""
    require(isinstance(entry, dict), 'entry must be an object')
    sig = entry.get('signature') or {}
    require(sig.get('alg') == 'ES256', 'unsupported signature algorithm')
    key_id = sig.get('keyId')
    require(key_id in PRODUCTS[product]['keys'] and key_id in keys, f'untrusted key {key_id!r}')
    try:
        raw = base64.b64decode(entry['statement'], validate=True)
        der = base64.b64decode(sig['der'], validate=True)
    except (KeyError, ValueError) as error:
        raise CatalogError(f'bad base64: {error}') from error
    require(p256.verify(keys[key_id], raw, der), f"bad signature for {entry.get('id')}")
    s = json.loads(raw)
    check_statement(s, product)
    # Unsigned mirror fields must agree exactly with the signed statement.
    for field in ('id', 'version', 'packageRevision', 'hardware', 'channel', 'installable'):
        require(entry.get(field) == s[field], f"{s['id']}: entry {field} disagrees with statement")
    asset = entry.get('asset') or {}
    for field in ('name', 'bytes', 'sha256'):
        require(asset.get(field) == s['asset'][field], f"{s['id']}: asset {field} disagrees with statement")
    require(entry.get('tag') == tag(product, s['id']), f"{s['id']}: tag mismatch")
    require(asset.get('url') == DOWNLOAD + entry['tag'] + '/' + s['asset']['name'], f"{s['id']}: noncanonical asset URL")
    if 'md5' in asset:  # unsigned transport check required by Glyph's factory update card
        require(isinstance(asset['md5'], str) and re.fullmatch(r'[0-9a-f]{32}', asset['md5']), f"{s['id']}: bad md5")
    if 'apiURL' in asset:
        require(re.fullmatch(re.escape(ASSET_API) + r'[1-9][0-9]{0,11}', asset['apiURL'] or ''), f"{s['id']}: bad apiURL")
    require(type(entry.get('withdrawn')) is bool, 'withdrawn must be boolean')
    extra = entry.get('extraAssets', [])
    require(isinstance(extra, list) and all(isinstance(n, str) and ASSET_NAME.fullmatch(n) for n in extra)
            and s['asset']['name'] not in extra and len(set(extra)) == len(extra), f"{s['id']}: bad extraAssets")
    require(isinstance(entry.get('details', {}), dict), 'details must be an object')
    return s


def load_keys():
    keys = {}
    for path in sorted((ROOT / 'keys').glob('*.x963')):
        raw = path.read_bytes()
        p256.public_point(raw)
        keys[path.stem] = raw
    return keys


def validate_catalog(product, catalog, keys):
    require(product in PRODUCTS, f'unknown product {product}')
    require(catalog.get('schemaVersion') == 1 and catalog.get('product') == product, 'bad catalog header')
    require(catalog.get('hardware') == PRODUCTS[product]['hardware'], 'bad catalog hardware')
    releases = catalog.get('releases')
    require(isinstance(releases, list), 'releases must be a list')
    seen = set()
    for entry in releases:
        s = verify_entry(product, entry, keys)
        require(s['id'] not in seen, f"duplicate release id {s['id']}")
        seen.add(s['id'])
    return len(releases)


def read(product):
    return json.loads(catalog_path(product).read_text())


def write(product, catalog):
    validate_catalog(product, catalog, load_keys())
    catalog_path(product).write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + '\n')


def empty(product):
    return {'schemaVersion': 1, 'product': product, 'hardware': PRODUCTS[product]['hardware'], 'releases': []}


if __name__ == '__main__':
    keys = load_keys()
    for product in PRODUCTS:
        path = catalog_path(product)
        count = validate_catalog(product, json.loads(path.read_text()), keys) if path.exists() else 0
        print(f'{product}: {count} signed releases verified')
