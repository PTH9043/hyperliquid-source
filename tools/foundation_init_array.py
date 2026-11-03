#!/usr/bin/env python3
'''Re-derive node #115 .init_array registration evidence (RE-001).

Packet: research/work-items/RE-001-node115-init-array.

The pinned binary is read, never executed.  From its bytes this checker
re-derives the target identity, every .init_array slot and the
R_X86_64_RELATIVE addend binding it to an initializer, each initializer FDE
extent (the half-open range of the covering .eh_frame FDE, never the next
unwind-index start), the raw FDE/CIE record bytes, the frame-link field and
the table counts.  It then compares every value recorded in the packet
evidence.json and proves that altered claims are rejected.  Absent packet
files are a hard failure.
'''

import bisect
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

BIN = Path('artifacts/node/115/hl-node')
EVIDENCE = Path('research/work-items/RE-001-node115-init-array/evidence.json')
TARGET_PATH = 'artifacts/node/115/hl-node'
EXPECTED_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
EXPECTED_SIZE = 105896032
ANCHOR_NEEDLE = 'St5ctypeIcE'
POLICY = 'target-and-dependency-totals-only'
DETAIL_KEYS = ('start', 'end', 'record_loc', 'record_bytes', 'cie_loc', 'cie_bytes', 'link_field', 'frame_link')


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def native(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def parse_sections(text):
    table = {}
    for line in text.splitlines():
        if ']' not in line:
            continue
        parts = line.split(']', 1)[1].split()
        if len(parts) < 5:
            continue
        try:
            row = {'type': parts[1], 'va': int(parts[2], 16),
                   'file_offset': int(parts[3], 16), 'size': int(parts[4], 16)}
        except ValueError:
            continue
        if parts[0] in table:
            raise AssertionError('duplicate section row: ' + parts[0])
        table[parts[0]] = row
    if not table:
        raise AssertionError('readelf -SW produced no section rows')
    return table


def parse_frames(text):
    cies = {}
    fdes = []
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3] == 'CIE':
            try:
                cies[int(parts[0], 16)] = int(parts[1], 16)
            except ValueError:
                continue
            continue
        if len(parts) < 6 or parts[3] != 'FDE':
            continue
        if not parts[4].startswith('cie=') or not parts[5].startswith('pc='):
            continue
        span = parts[5][3:].split('..')
        if len(span) != 2:
            continue
        try:
            row = {'loc': int(parts[0], 16), 'length': int(parts[1], 16),
                   'cie': int(parts[4][4:], 16), 'start': int(span[0], 16),
                   'end': int(span[1], 16)}
        except ValueError:
            continue
        if row['loc'] in seen:
            raise AssertionError('duplicate FDE record at 0x%x' % row['loc'])
        seen.add(row['loc'])
        fdes.append(row)
    return cies, fdes


def relative_slots(text, low, high):
    slots = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != 'R_X86_64_RELATIVE':
            continue
        try:
            offset = int(parts[0], 16)
        except ValueError:
            continue
        if not low <= offset < high:
            continue
        if offset in slots:
            raise AssertionError('duplicate RELATIVE slot 0x%x in .init_array' % offset)
        token = parts[3]
        if token.startswith('+'):
            token = token[1:]
        slots[offset] = int(token, 16)
    return slots


def dynsym_anchor(text, needle):
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8 or not parts[0].endswith(':'):
            continue
        if parts[3] != 'FUNC' or needle not in parts[7]:
            continue
        try:
            return {'name': parts[7], 'value': int(parts[1], 16), 'size': int(parts[2], 16)}
        except ValueError:
            continue
    return None


def frame_record(whole, eh, loc, length):
    if length is None:
        return None
    start = eh['file_offset'] + loc
    if start + 4 + length > len(whole):
        return None
    return whole[start:start + 4 + length].hex()


def derive(whole, sections, cies, fdes, slots, target_sha256, anchor):
    eh = sections['.eh_frame']
    init = sections['.init_array']
    order = sorted(range(len(fdes)), key=lambda i: fdes[i]['start'])
    starts = [fdes[i]['start'] for i in order]
    entries = []
    for slot in sorted(slots):
        target = slots[slot]
        owner = None
        pos = bisect.bisect_right(starts, target) - 1
        if pos >= 0:
            candidate = fdes[order[pos]]
            if candidate['start'] <= target < candidate['end']:
                owner = candidate
        fde = None
        if owner is not None:
            loc = owner['loc']
            record = frame_record(whole, eh, loc, owner['length'])
            cie_length = cies.get(owner['cie'])
            cie_record = frame_record(whole, eh, owner['cie'], cie_length)
            field = None
            if record is not None and len(record) >= 16:
                field = int.from_bytes(bytes.fromhex(record[8:16]), 'little')
            link = 'unchecked'
            if field is not None:
                link = 'ok' if field == loc + 4 - owner['cie'] else 'mismatch'
            fde = {'start': owner['start'], 'end': owner['end'],
                   'bytes': owner['end'] - owner['start'], 'record_loc': loc,
                   'record_bytes': record, 'cie_loc': owner['cie'],
                   'cie_length': cie_length, 'cie_bytes': cie_record,
                   'link_field': field, 'frame_link': link}
        entries.append({'slot': slot, 'target': target, 'kind': 'relocation', 'fde': fde})
    digest = hashlib.sha256()
    for entry in entries:
        fde = entry['fde']
        if fde is None:
            digest.update(('%x %x none\n' % (entry['slot'], entry['target'])).encode('ascii'))
        else:
            digest.update(('%x %x %x %x\n' % (entry['slot'], entry['target'], fde['start'], fde['end'])).encode('ascii'))
    with_fde = sum(1 for entry in entries if entry['fde'] is not None)
    return {'path': TARGET_PATH, 'size': len(whole), 'sha256': target_sha256,
            'sections': {'eh_frame': {'va': eh['va'], 'size': eh['size']},
                         'init_array': {'va': init['va'], 'file_offset': init['file_offset'], 'size': init['size']}},
            'counts': {'entries': len(entries), 'relative_slots': len(slots),
                       'with_fde': with_fde, 'without_fde': len(entries) - with_fde,
                       'fde_count': len(fdes), 'cie_count': len(cies)},
            'entry_map_sha256': digest.hexdigest(), 'anchor': anchor, 'entries': entries}


def norm(value):
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16)
        except ValueError:
            return text.lower()
    return value


def check(evidence, derived):
    violations = []

    def want(label, recorded, actual):
        if norm(recorded) != norm(actual):
            violations.append('%s: recorded %r != derived %r' % (label, recorded, actual))

    def block(container, key, label):
        if isinstance(container, dict) and isinstance(container.get(key), (dict, list)):
            return container[key]
        violations.append(label + ' is missing')
        return {}

    if not isinstance(evidence, dict):
        return ['evidence root is not an object']

    target = block(evidence, 'target', 'target')
    for key in ('path', 'size', 'sha256'):
        want('target.' + key, target.get(key), derived[key])

    sections = block(evidence, 'sections', 'sections')
    eh_sec = block(sections, 'eh_frame', 'sections.eh_frame')
    for key in ('va', 'size'):
        want('sections.eh_frame.' + key, eh_sec.get(key), derived['sections']['eh_frame'][key])
    init_sec = block(sections, 'init_array', 'sections.init_array')
    for key in ('va', 'file_offset', 'size'):
        want('sections.init_array.' + key, init_sec.get(key), derived['sections']['init_array'][key])

    init = block(evidence, 'init_array', 'init_array')
    for key in ('entries', 'relative_slots', 'with_fde', 'without_fde'):
        want('init_array.' + key, init.get(key), derived['counts'][key])
    want('init_array.entry_map_sha256', init.get('entry_map_sha256'), derived['entry_map_sha256'])

    frames = block(evidence, 'frames', 'frames')
    for key in ('fde_count', 'cie_count'):
        want('frames.' + key, frames.get(key), derived['counts'][key])

    dependency = block(evidence, 'dependency', 'dependency')
    if not dependency.get('name'):
        violations.append('dependency.name is empty')
    want('dependency.counts_as', dependency.get('counts_as'), POLICY)
    if dependency.get('symbol_name') is not None:
        anchor = derived['anchor'] or {}
        want('dependency.symbol_name', dependency.get('symbol_name'), anchor.get('name'))
        want('dependency.symbol_value', dependency.get('symbol_value'), anchor.get('value'))

    detail = block(evidence, 'detail_entries', 'detail_entries')
    if not isinstance(detail, list):
        violations.append('detail_entries is not a list')
        return violations
    seen = set()
    for item in detail:
        if not isinstance(item, dict):
            violations.append('detail entry is not an object')
            continue
        index = item.get('index')
        if not isinstance(index, int) or not 0 <= index < len(derived['entries']):
            violations.append('detail entry index out of range: %r' % (index,))
            continue
        if index in seen:
            violations.append('detail entry repeats index %d' % index)
            continue
        seen.add(index)
        actual = derived['entries'][index]
        label = 'detail[%d]' % index
        want(label + '.slot', item.get('slot'), actual['slot'])
        want(label + '.target', item.get('target'), actual['target'])
        recorded_fde = item.get('fde')
        actual_fde = actual['fde']
        if (recorded_fde is None) != (actual_fde is None):
            violations.append(label + '.fde presence differs from the pinned bytes')
        elif actual_fde is not None and not isinstance(recorded_fde, dict):
            violations.append(label + '.fde is not an object')
        elif actual_fde is not None:
            for key in DETAIL_KEYS:
                want(label + '.fde.' + key, recorded_fde.get(key), actual_fde[key])
    return violations


def bump_hex(value, delta):
    return hex(norm(value) + delta)


def flip_last(text):
    if not text:
        raise AssertionError('cannot corrupt an empty record')
    last = text[-1]
    return text[:-1] + ('0' if last != '0' else '1')


def controls(evidence, derived):
    detail = evidence.get('detail_entries')
    if not isinstance(detail, list) or not detail:
        raise AssertionError('no recorded detail entries to corrupt')
    recorded = sorted(item['index'] for item in detail
                      if isinstance(item, dict) and isinstance(item.get('index'), int))
    fde_index = None
    for index in recorded:
        fde = derived['entries'][index]['fde']
        if fde is not None and fde['record_bytes'] and fde['cie_bytes']:
            fde_index = index
            break
    if fde_index is None:
        raise AssertionError('no recorded detail entry carries FDE and CIE bytes')
    reports = []

    def item_for(doc, index):
        for item in doc['detail_entries']:
            if item.get('index') == index:
                return item
        raise KeyError('detail entry %d' % index)

    def mutate(name, apply):
        doc = copy.deepcopy(evidence)
        apply(doc)
        violations = check(doc, derived)
        if not violations:
            raise AssertionError('corruption control was accepted: ' + name)
        reports.append((name, violations[0]))

    mutate('target digest', lambda doc: doc['target'].__setitem__('sha256', '0' * 64))
    mutate('target size', lambda doc: doc['target'].__setitem__('size', doc['target']['size'] + 1))
    mutate('init_array entry count', lambda doc: doc['init_array'].__setitem__('entries', doc['init_array']['entries'] + 1))
    mutate('entry-map digest', lambda doc: doc['init_array'].__setitem__('entry_map_sha256', 'f' * 64))
    mutate('slot address', lambda doc: item_for(doc, recorded[0]).__setitem__('slot', bump_hex(item_for(doc, recorded[0])['slot'], 8)))
    mutate('entry target', lambda doc: item_for(doc, recorded[0]).__setitem__('target', bump_hex(item_for(doc, recorded[0])['target'], 1)))
    mutate('fde extent end', lambda doc: item_for(doc, fde_index)['fde'].__setitem__('end', bump_hex(item_for(doc, fde_index)['fde']['end'], 1)))
    mutate('fde record byte', lambda doc: item_for(doc, fde_index)['fde'].__setitem__('record_bytes', flip_last(item_for(doc, fde_index)['fde']['record_bytes'])))
    mutate('cie record byte', lambda doc: item_for(doc, fde_index)['fde'].__setitem__('cie_bytes', flip_last(item_for(doc, fde_index)['fde']['cie_bytes'])))
    mutate('frame-link field', lambda doc: item_for(doc, fde_index)['fde'].__setitem__('link_field', norm(item_for(doc, fde_index)['fde']['link_field']) + 1))
    if isinstance(evidence.get('dependency'), dict) and evidence['dependency'].get('symbol_value') is not None:
        mutate('dependency symbol value', lambda doc: doc['dependency'].__setitem__('symbol_value', '0x1'))
    return reports


def describe(index, entry):
    fde = entry['fde']
    if fde is None:
        return 'derived entry[%d]: slot=0x%x target=0x%x fde=none' % (index, entry['slot'], entry['target'])
    return ('derived entry[%d]: slot=0x%x target=0x%x fde=0x%x..0x%x bytes=%d record_loc=0x%x cie_loc=0x%x cie_length=%s link=%s record=%s cie=%s'
            % (index, entry['slot'], entry['target'], fde['start'], fde['end'], fde['bytes'],
               fde['record_loc'], fde['cie_loc'], fde['cie_length'], fde['frame_link'],
               fde['record_bytes'], fde['cie_bytes']))


def main():
    if not BIN.is_file():
        raise AssertionError('pinned target is absent: ' + str(BIN))
    whole = BIN.read_bytes()
    if len(whole) != EXPECTED_SIZE:
        raise AssertionError('target size mismatch: %d' % len(whole))
    digest = sha256_file(BIN)
    if digest != EXPECTED_SHA:
        raise AssertionError('target digest mismatch: ' + digest)
    print('target path : ' + TARGET_PATH)
    print('target bytes: %d' % len(whole))
    print('target sha256: ' + digest)

    sections = parse_sections(native('readelf', '-SW', str(BIN)))
    for name in ('.eh_frame', '.init_array', '.rela.dyn'):
        if name not in sections:
            raise AssertionError('required section absent: ' + name)
    init = sections['.init_array']
    if init['size'] < 8 or init['size'] % 8:
        raise AssertionError('.init_array size is not a positive multiple of 8: %d' % init['size'])
    slots = relative_slots(native('readelf', '-Wr', str(BIN)), init['va'], init['va'] + init['size'])
    if len(slots) != init['size'] // 8:
        raise AssertionError('unresolved .init_array slots: %d of %d' % (len(slots), init['size'] // 8))
    cies, fdes = parse_frames(native('readelf', '-W', '--debug-dump=frames', str(BIN)))
    if not fdes:
        raise AssertionError('no FDE records decoded from .eh_frame')
    anchor = dynsym_anchor(native('readelf', '-sW', '--dyn-syms', str(BIN)), ANCHOR_NEEDLE)
    derived = derive(whole, sections, cies, fdes, slots, digest, anchor)

    counts = derived['counts']
    print('derived sections.eh_frame.va=0x%x size=%d' % (derived['sections']['eh_frame']['va'], derived['sections']['eh_frame']['size']))
    print('derived sections.init_array.va=0x%x file_offset=0x%x size=%d' % (init['va'], init['file_offset'], init['size']))
    print('derived counts.entries=%d relative_slots=%d with_fde=%d without_fde=%d fde_count=%d cie_count=%d'
          % (counts['entries'], counts['relative_slots'], counts['with_fde'], counts['without_fde'], counts['fde_count'], counts['cie_count']))
    print('derived entry_map_sha256=' + derived['entry_map_sha256'])
    if anchor:
        print('derived anchor=%s value=0x%x size=%d' % (anchor['name'], anchor['value'], anchor['size']))
    else:
        print('derived anchor=none')

    entries = derived['entries']
    selected = list(range(min(8, len(entries))))
    if len(entries) - 1 not in selected:
        selected.append(len(entries) - 1)
    for index, entry in enumerate(entries):
        if entry['fde'] is None and index not in selected:
            selected.append(index)
    for index in selected:
        print(describe(index, entries[index]))
    mismatched = [index for index, entry in enumerate(entries)
                  if entry['fde'] is not None and entry['fde']['frame_link'] != 'ok']
    if mismatched:
        raise AssertionError('FDE frame-link mismatch at entries %r' % (mismatched[:5],))
    print('derived frame_link=ok for %d FDE extents' % counts['with_fde'])

    if not EVIDENCE.is_file():
        raise AssertionError('packet evidence is absent: ' + str(EVIDENCE))
    evidence = json.loads(EVIDENCE.read_text(encoding='utf-8'))
    violations = check(evidence, derived)
    if violations:
        for line in violations:
            print('VIOLATION ' + line)
        raise AssertionError('%d recorded claim(s) disagree with the pinned bytes' % len(violations))
    reports = controls(evidence, derived)
    for name, first in reports:
        print('control rejected: %s -> %s' % (name, first))
    print('OK: %d entries re-derived, %d corruption controls rejected' % (counts['entries'], len(reports)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
