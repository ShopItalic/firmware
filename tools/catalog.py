"""Catalog schema, signed release statements and validation.

Trust model: GitHub, TLS and this repository only decide *availability*.
Every release carries a statement (exact JSON bytes) signed by the product's
release key. Clients verify the signature over those bytes, parse them, and
trust only what the statement says. Unsigned entry fields are display
metadata. The unsigned fields clients honour can only narrow what a statement
grants: `withdrawn: true` removes an offer, an entry's `rollout` admits only
some Rings to an automatic install the statement allows, and the catalog's
`automaticUpdatesPaused` stops automatic installs.
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
# Version 2 adds what an app needs to install a release by itself (ShopItalic/app
# docs/design/ring-firmware-auto-update.md, section 9). Only Sudo uses it: Glyph
# firmware checks its own statements and knows version 1 only.
SCHEMA_V2 = 'italic-firmware-release/2'
CHANNELS = ('test', 'beta', 'stable')
# Product -> hardware, key IDs and statement schemas accepted in its catalog.
PRODUCTS = {
    'glyph': {'hardware': 'PKS3-101', 'keys': ('glyph-release-1',), 'schemas': (SCHEMA,)},
    'sudo': {'hardware': '603V1.23.2', 'keys': ('sudo-release-1',), 'schemas': (SCHEMA, SCHEMA_V2)},
}
SHA = re.compile(r'[0-9a-f]{64}')
RELEASE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+-]{0,47}')
ASSET_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}')
STATEMENT_KEYS = {'schema', 'product', 'hardware', 'id', 'version', 'packageRevision', 'channel',
                  'installable', 'asset', 'sourceVersions', 'issuedAt'}
# Version 2's required and optional fields:
#   autoInstall          the release may install itself (stable, installable, application only)
#   minimumAppBuild      the oldest app build that may install it
#   erasesStorage        its first boot formats the device's recording storage
#   applicationOnly      the package replaces the application only, never the bootloader or SoftDevice
#   buildIdentity        what the device reports once it runs this release
#   minimumSourceRevision  (optional) the oldest revision of its generation it may replace
#   customerVersion      (optional, never on test) the name people see, such as "1.1"
#   changeNote           (optional) one short line of what people will feel or see
V2_REQUIRED = {'autoInstall', 'minimumAppBuild', 'erasesStorage', 'applicationOnly', 'buildIdentity'}
V2_OPTIONAL = {'minimumSourceRevision', 'customerVersion', 'changeNote'}
BUILD_IDENTITY_KEYS = {'generation', 'revision', 'codec', 'settingsSchema', 'buildID'}
PAUSES = ('all', 'background')


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
                   issued_at, source_versions=None, automatic=None):
    """`automatic` holds version 2's fields; without it the statement is version 1."""
    statement = {'schema': SCHEMA if automatic is None else SCHEMA_V2, 'product': product,
                 'hardware': PRODUCTS[product]['hardware'],
                 'id': release_id, 'version': version, 'packageRevision': revision,
                 'channel': channel, 'installable': installable,
                 'asset': {'name': asset['name'], 'bytes': asset['bytes'], 'sha256': asset['sha256']},
                 'issuedAt': issued_at, **(automatic or {})}
    if source_versions is not None:
        statement['sourceVersions'] = list(source_versions)
    check_statement(statement, product)
    return statement


def check_statement(s, product):
    require(isinstance(s, dict), 'statement must be an object')
    require(s.get('schema') in PRODUCTS[product]['schemas'], 'wrong statement schema')
    allowed = STATEMENT_KEYS | (V2_REQUIRED | V2_OPTIONAL if s['schema'] == SCHEMA_V2 else set())
    require(set(s) <= allowed, 'unexpected statement fields')
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
    if s['schema'] == SCHEMA_V2:
        check_automatic(s)


def check_automatic(s):
    """Version 2's fields. They decide installs nobody taps, so each is exact."""
    require(V2_REQUIRED <= set(s), 'version 2 statement fields missing')
    for field in ('autoInstall', 'erasesStorage', 'applicationOnly'):
        require(type(s[field]) is bool, f'{field} must be boolean')
    require(type(s['minimumAppBuild']) is int and 1 <= s['minimumAppBuild'] <= 999999, 'bad minimumAppBuild')
    if s['autoInstall']:
        require(s['channel'] == 'stable' and s['installable'] and s['applicationOnly'],
                'autoInstall needs an installable, application-only stable release')
    identity = s['buildIdentity']
    require(isinstance(identity, dict) and set(identity) == BUILD_IDENTITY_KEYS, 'bad buildIdentity')
    for field, top in (('generation', 99), ('revision', 999), ('codec', 255), ('settingsSchema', 255)):
        require(type(identity[field]) is int and 0 <= identity[field] <= top, f'bad buildIdentity {field}')
    require(isinstance(identity['buildID'], str) and re.fullmatch(r'[0-9a-f]{32}', identity['buildID']),
            'bad buildIdentity buildID')
    generation = re.fullmatch(r'\d+\.\d+\.\d+\.\d+P(\d{2})', s['version'])
    require(generation is not None and int(generation.group(1)) == identity['generation']
            and identity['revision'] == s['packageRevision'], 'buildIdentity disagrees with version or revision')
    if 'minimumSourceRevision' in s:
        require(type(s['minimumSourceRevision']) is int and 1 <= s['minimumSourceRevision'] <= 999,
                'bad minimumSourceRevision')
    if 'customerVersion' in s:
        require(s['channel'] != 'test' and isinstance(s['customerVersion'], str)
                and re.fullmatch(r'[1-9][0-9]{0,2}\.[0-9]{1,3}', s['customerVersion']),
                'customerVersion must look like 1.1, and never on the test channel')
    if 'changeNote' in s:
        note = s['changeNote']
        require(isinstance(note, str) and 0 < len(note) <= 60 and note == note.strip() and note.isprintable(),
                'changeNote must be one printable line of at most 60 characters')


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
    if s['schema'] == SCHEMA_V2 and 'buildIdentity' in entry.get('details', {}):
        require(entry['details']['buildIdentity'] == s['buildIdentity'],
                f"{s['id']}: details buildIdentity disagrees with statement")
    if 'rollout' in entry:
        check_rollout(s, entry['rollout'])
    return s


def check_rollout(s, rollout):
    """`rollout` admits devices whose bucket (0-99) is below `percent` to an
    automatic install. Unsigned, so it means something only beside a signed
    `autoInstall`; a missing rollout is 0%."""
    require(s['schema'] == SCHEMA_V2 and s['autoInstall'], f"{s['id']}: rollout without a signed autoInstall")
    require(isinstance(rollout, dict) and 'percent' in rollout and set(rollout) <= {'percent', 'since'},
            f"{s['id']}: bad rollout")
    require(type(rollout['percent']) is int and 0 <= rollout['percent'] <= 100, f"{s['id']}: bad rollout percent")
    if 'since' in rollout:
        require(isinstance(rollout['since'], str) and re.fullmatch(r'\d{4}-\d\d-\d\d', rollout['since']),
                f"{s['id']}: rollout since must be a date, e.g. 2026-11-02")


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
    # The pause switch: "all" stops every automatic install, "background" only
    # those an app would start in a background window. Missing: not paused.
    pause = catalog.get('automaticUpdatesPaused')
    require(pause is None or pause in PAUSES, 'automaticUpdatesPaused must be "all" or "background"')
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
