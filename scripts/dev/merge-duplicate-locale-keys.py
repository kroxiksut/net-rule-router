#!/usr/bin/env python3
"""Merge duplicate top-level keys in locale JSON files.

Issue: locales/{en,ru}.json each have TWO top-level "dialog" blocks.
JSON spec leaves duplicate-key behavior undefined; Python's json.load
keeps the LAST occurrence, silently dropping the first block's keys.
That's why dialog.load-list.* RU translations weren't appearing in
the UI even though they were present in the source file.

This script reads each locale with a custom hook that deep-merges
duplicate keys (later occurrences win on leaf conflicts but nested
dicts are merged together), then writes the result back with stable
indent=2 formatting.
"""
import json
from collections import OrderedDict


def merge_duplicates(pairs):
    """object_pairs_hook that deep-merges duplicate keys."""
    result = OrderedDict()
    for key, value in pairs:
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            def deep_merge(target, src):
                for k, v in src.items():
                    if k in target and isinstance(target[k], dict) and isinstance(v, dict):
                        deep_merge(target[k], v)
                    else:
                        target[k] = v
                return target
            deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def main():
    for path in ('locales/en.json', 'locales/ru.json'):
        with open(path, 'r', encoding='utf-8-sig') as fh:
            data = json.load(fh, object_pairs_hook=merge_duplicates)
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write('\n')
        print(f'merged: {path}')


if __name__ == '__main__':
    main()
