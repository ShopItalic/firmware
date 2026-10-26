"""Catalog schema, signed release statements and validation.

Trust model: GitHub, TLS and this repository only decide *availability*.
Every release carries a statement (exact JSON bytes) signed by the product's
release key. Clients verify the signature over those bytes, parse them, and
trust only what the statement says. Unsigned entry fields are display
metadata. The unsigned fields clients honour can only narrow what a statement
grants: `withdrawn: true` removes an offer, an entry's `rollout` admits only
some Rings to an automatic install the statement allows, and the catalog's
`automaticUpdatesPaused` stops automatic installs.

A product may also carry a signed policy (`policy-v1.json`, and the same
envelope as the catalog's `policy`): a floor below which nothing installs,
withdrawals, and the signed ceiling of each automatic rollout. Apps remember
the newest policy they have seen, so neither a push nor an older copy of the
catalog can undo it.
"""
import base64
import json
import re
import subprocess
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
#   customerVersion      (optional, never on test) the name people see, major.subrelease.increment
#                        ("1.0.124"); the app also reads the two-part form ("1.120") of earlier fixtures
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
                and re.fullmatch(r'[1-9][0-9]{0,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?', s['customerVersion']),
                'customerVersion must look like 1.0.124, and never on the test channel')
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


# Signed policy (ShopItalic/app docs/design/ring-firmware-stable-release.md,
# 1.1). Three catalog controls are unsigned, so anyone who can push, or serve
# an older catalog, could un-withdraw a release, widen a rollout or restore an
# old state. The policy is signed with the product's release key and carries a
# sequence; apps keep the highest sequence they have seen, every withdrawal
# (signed or not) and the highest floor, plus a baseline compiled into each
# build. `policy-v1.json` is its source, and the catalog carries the same
# envelope under `policy`, so an app reads both in one fetch.
POLICY_SCHEMA = 'italic-firmware-policy/1'
POLICY_PRODUCTS = ('sudo',)
POLICY_KEYS = {'schema', 'product', 'hardware', 'sequence', 'issuedAt', 'minimumRevision', 'withdrawn', 'rollout'}
ENVELOPE_KEYS = {'schemaVersion', 'product', 'hardware', 'statement', 'signature'}
POLICY_STATEMENT_BYTES = 4096  # tools/sign_release.swift signs nothing larger
POLICY_SEQUENCE_MAX = 2**31 - 1  # the app's limit
P_VERSION = re.compile(r'\d+\.\d+\.\d+\.\d+P(\d{2})')
# A revision above 100 rebuilds source revision `revision - 100` with another
# compiler (P21-rc.107 is rc.7), so it ranks with its source, as in the app.
COMPILER_REBUILD_OFFSET = 100


def policy_path(product):
    return ROOT / 'products' / product / 'policy-v1.json'


def make_policy(product, sequence, issued_at, minimum_revision, withdrawn, rollout):
    return {'schema': POLICY_SCHEMA, 'product': product, 'hardware': PRODUCTS[product]['hardware'],
            'sequence': sequence, 'issuedAt': issued_at, 'minimumRevision': dict(minimum_revision),
            'withdrawn': sorted(withdrawn, key=lambda w: w['id']), 'rollout': dict(rollout)}


def check_policy_statement(s, product):
    """The statement's own rules, with every field exact. Apps apply the
    fields they know and ignore others, which is safe because a field only
    narrows. A field that changes how a known one reads goes in a new schema,
    published beside version 1 for as long as apps read only version 1."""
    require(product in POLICY_PRODUCTS, f'{product} has no signed policy')
    require(isinstance(s, dict) and set(s) == POLICY_KEYS, 'policy fields missing or unexpected')
    require(s['schema'] == POLICY_SCHEMA, 'wrong policy schema')
    require(s['product'] == product and s['hardware'] == PRODUCTS[product]['hardware'], 'policy product/hardware mismatch')
    require(type(s['sequence']) is int and 1 <= s['sequence'] <= POLICY_SEQUENCE_MAX,
            f'policy sequence must be 1 to {POLICY_SEQUENCE_MAX}')
    require(isinstance(s['issuedAt'], str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', s['issuedAt']),
            'policy issuedAt must be UTC seconds, e.g. 2026-10-26T12:00:00Z')
    floors = s['minimumRevision']
    require(isinstance(floors, dict) and all(isinstance(g, str) and re.fullmatch(r'[1-9][0-9]?', g)
                                             and type(r) is int and 1 <= r <= 999 for g, r in floors.items()),
            'minimumRevision maps a generation ("21") to a package revision (124)')
    withdrawn = s['withdrawn']
    require(isinstance(withdrawn, list) and all(
        isinstance(w, dict) and set(w) == {'id', 'sha256'} and isinstance(w['id'], str) and RELEASE_ID.fullmatch(w['id'])
        and isinstance(w['sha256'], str) and SHA.fullmatch(w['sha256']) for w in withdrawn),
        'withdrawn lists {"id", "sha256"} pairs')
    require([w['id'] for w in withdrawn] == sorted({w['id'] for w in withdrawn})
            and len({w['sha256'] for w in withdrawn}) == len(withdrawn),
            'withdrawn is sorted by id, with no id or package twice')
    rollout = s['rollout']
    require(isinstance(rollout, dict) and all(isinstance(i, str) and RELEASE_ID.fullmatch(i)
                                              and type(p) is int and 0 <= p <= 100 for i, p in rollout.items()),
            'rollout maps a release id to a percentage from 0 to 100')


def verify_policy(product, envelope, keys):
    """Verify a policy envelope; return its statement and the exact signed bytes."""
    require(isinstance(envelope, dict) and set(envelope) == ENVELOPE_KEYS, 'bad policy envelope')
    require(envelope['schemaVersion'] == 1 and envelope['product'] == product
            and envelope['hardware'] == PRODUCTS[product]['hardware'], 'bad policy envelope header')
    sig = envelope['signature']
    require(isinstance(sig, dict) and set(sig) == {'alg', 'keyId', 'der'} and sig['alg'] == 'ES256',
            'unsupported policy signature')
    require(sig['keyId'] in PRODUCTS[product]['keys'] and sig['keyId'] in keys, f"untrusted key {sig['keyId']!r}")
    try:
        raw = base64.b64decode(envelope['statement'], validate=True)
        der = base64.b64decode(sig['der'], validate=True)
    except (TypeError, ValueError) as error:
        raise CatalogError(f'bad policy base64: {error}') from error
    require(len(raw) <= POLICY_STATEMENT_BYTES, f'policy statement over {POLICY_STATEMENT_BYTES} bytes')
    require(p256.verify(keys[sig['keyId']], raw, der), 'bad policy signature')
    s = json.loads(raw)
    check_policy_statement(s, product)
    return s, raw


def rank(version, revision):
    """The app's order: generation, source revision, revision. Images before
    the P series (Z62) rank below every generation."""
    match = P_VERSION.fullmatch(version)
    source = revision - COMPILER_REBUILD_OFFSET if revision > COMPILER_REBUILD_OFFSET else revision
    return (int(match.group(1)), source, revision) if match else (0, 0, revision)


def floor_cut(policy):
    """The highest floor's rank: everything ranked below it is below the floor."""
    floors = policy['minimumRevision']
    if not floors:
        return None
    generation, revision = max(((int(g), r) for g, r in floors.items()),
                               key=lambda item: rank(f'6.0.3.3P{item[0]:02d}', item[1]))
    return rank(f'6.0.3.3P{generation:02d}', revision)


def below_floor(policy, s):
    cut = floor_cut(policy)
    return cut is not None and rank(s['version'], s['packageRevision']) < cut


def check_policy_against_catalog(product, policy, releases, keys):
    """What the policy names must be in the catalog as it says, and the unsigned
    controls must say no more than it does: builds before the policy read only
    those (App 263 and later read an entry's rollout and withdrawn)."""
    statements = {}
    for entry in releases:
        statements[entry['id']] = (entry, verify_entry(product, entry, keys))
    for w in policy['withdrawn']:
        require(w['id'] in statements, f"withdrawn {w['id']} is not in the catalog")
        entry, s = statements[w['id']]
        require(s['asset']['sha256'] == w['sha256'], f"withdrawn {w['id']}: the catalog's package is another")
        require(entry['withdrawn'] is True, f"withdrawn {w['id']}: its entry must say withdrawn: true too")
    # A floor names a published installable release, so it never passes every
    # release there is. Withdrawing it later (unsigned, at once) stays possible:
    # release.py policy is what requires one still offered at the floor.
    for generation, revision in policy['minimumRevision'].items():
        require(any(rank(s['version'], s['packageRevision'])[0] == int(generation) and s['packageRevision'] == revision
                    and s['installable'] for _, s in statements.values()),
                f'floor {generation}:{revision} names no installable release in the catalog')
    for release_id in policy['rollout']:
        require(release_id in statements, f'rollout {release_id} is not in the catalog')
        _, s = statements[release_id]
        require(s['schema'] == SCHEMA_V2 and s['autoInstall'], f'rollout {release_id}: not a signed automatic release')
    for release_id, (entry, s) in statements.items():
        unsigned = (entry.get('rollout') or {}).get('percent', 0)
        require(unsigned <= policy['rollout'].get(release_id, 0),
                f"{release_id}: its unsigned rollout ({unsigned}%) is above the signed ceiling "
                f"({policy['rollout'].get(release_id, 0)}%); raise it with release.py policy --rollout")


def check_policy_history(previous, policy):
    """A policy replaces only an older one, and keeps what apps already keep:
    every withdrawal and at least the floor. `previous` may be None."""
    if previous is None:
        return
    if policy == previous:
        return
    require(policy['sequence'] > previous['sequence'],
            f"policy sequence {policy['sequence']} must be above the previous {previous['sequence']}")
    kept = {(w['id'], w['sha256']) for w in policy['withdrawn']}
    require(all((w['id'], w['sha256']) in kept for w in previous['withdrawn']),
            "a withdrawal can't be undone (apps keep it); publish the next revision instead")
    old, new = floor_cut(previous), floor_cut(policy)
    require(old is None or (new is not None and new >= old), 'the floor can only rise (apps keep the highest)')


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
    if 'policy' in catalog:
        policy, _ = verify_policy(product, catalog['policy'], keys)
        check_policy_against_catalog(product, policy, releases, keys)
    return len(releases)


# What the apps read, from their sources in ShopItalic/app. A catalog over a
# limit isn't read at all by builds with it (the download or decode fails), so
# these stay at the strictest limit of any build still in use. `kept`: verified
# entries past it are dropped, oldest first.
APP_LIMITS = {
    # RingFirmwareRelease.maximumCatalogBytes; RingSignedFirmwareCatalog.decode
    # (entries.count <= 200, releases.prefix(100)). ShopItalic/app branch
    # claude/wizardly-jennings-fddc3e raises them to 8 MiB and the newest 1,000
    # entries; keep these until no build in use predates it.
    'sudo': {'bytes': 512 * 1024, 'entries': 200, 'kept': 100},
    # GlyphFirmwareCatalog.maximumCatalogBytes, entries.count <= 500.
    'glyph': {'bytes': 512 * 1024, 'entries': 500, 'kept': 500},
}
LIMIT_WARNING = 0.75


def check_size(product, size, entries):
    """Raise past an app's limit; return warnings from 75% of it."""
    limits = APP_LIMITS[product]
    require(size <= limits['bytes'], f"{product}: the catalog is {size:,} bytes; apps read at most {limits['bytes']:,}")
    require(entries <= limits['entries'], f"{product}: {entries} entries; apps read at most {limits['entries']}")
    warnings = []
    if size > limits['bytes'] * LIMIT_WARNING:
        warnings.append(f"{product}: the catalog is {size:,} bytes, {size / limits['bytes']:.0%} of the "
                        f"{limits['bytes']:,} apps read; retire old entries before it reaches the limit")
    if entries > limits['kept'] * LIMIT_WARNING:
        warnings.append(f"{product}: {entries} entries; apps keep the newest {limits['kept']} and drop the rest")
    return warnings


def read_policy(product):
    path = policy_path(product)
    return json.loads(path.read_text()) if path.exists() else None


def previous_policy(product, ref, keys):
    """The policy at git `ref`, verified, or None when there was none."""
    path = policy_path(product).relative_to(ROOT).as_posix()
    shown = subprocess.run(['git', '-C', str(ROOT), 'show', f'{ref}:{path}'], capture_output=True, text=True)
    if shown.returncode != 0:
        listed = subprocess.run(['git', '-C', str(ROOT), 'cat-file', '-e', f'{ref}^{{commit}}'], capture_output=True)
        require(listed.returncode == 0, f'{ref} is not a commit here; fetch the history (fetch-depth: 0)')
        return None
    return verify_policy(product, json.loads(shown.stdout), keys)[0]


def check_repository(keys, previous_ref=None):
    """Every catalog, its size, and each policy: the file and the catalog's
    copy are one envelope, and it replaces only the policy at `previous_ref`."""
    report, warnings = [], []
    for product in PRODUCTS:
        path = catalog_path(product)
        if not path.exists():
            report.append(f'{product}: 0 signed releases verified')
            continue
        raw = path.read_bytes()
        current = json.loads(raw)
        envelope = read_policy(product)
        require(envelope == current.get('policy'), f"{product}: policy-v1.json and the catalog's policy differ")
        count = validate_catalog(product, current, keys)
        warnings += check_size(product, len(raw), count)
        report.append(f'{product}: {count} signed releases verified')
        policy = verify_policy(product, envelope, keys)[0] if envelope is not None else None
        if previous_ref is not None:
            before = previous_policy(product, previous_ref, keys)
            require(before is None or policy is not None, f"{product}: the signed policy can't be removed")
            if policy is not None:
                check_policy_history(before, policy)
        if policy is not None:
            report.append(f"{product}: policy {policy['sequence']} verified")
    return report, warnings


def read(product):
    return json.loads(catalog_path(product).read_text())


def write(product, catalog):
    validate_catalog(product, catalog, load_keys())
    catalog_path(product).write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + '\n')


def empty(product):
    return {'schemaVersion': 1, 'product': product, 'hardware': PRODUCTS[product]['hardware'], 'releases': []}


def previous_ref(given):
    """CI passes the base commit; a new branch's push has none (all zeros),
    so it is checked against origin/main."""
    if given is None or not given.strip('0'):
        return 'origin/main' if given is not None else None
    return given


if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Verify every catalog, its size and its signed policy.')
    parser.add_argument('--previous', help='the commit this one replaces: a policy may only follow its policy')
    args = parser.parse_args()
    try:
        report, warnings = check_repository(load_keys(), previous_ref(args.previous))
    except CatalogError as error:
        print(f'::error::{error}'); sys.exit(1)
    for line in report:
        print(line)
    for line in warnings:
        print(f'::warning::{line}')
