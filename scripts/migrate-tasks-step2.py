#!/usr/bin/env python3
"""Second pass: archive closed `#### Группа X:` sections inside Блок 16.

Idempotent: re-running has no effect once everything's archived.
Encoding: UTF-8 with BOM, careful to preserve everything outside the
target sections.
"""

import re
import sys

ENC = 'utf-8'
BOM = '﻿'

SOURCE = 'TASKS_RU.md'
ARCHIVE = 'OLD_TASKS_RU.md'


def read_file(path):
    with open(path, 'r', encoding=ENC) as f:
        text = f.read()
    has_bom = text.startswith(BOM)
    if has_bom:
        text = text[1:]
    return text, has_bom


def write_file(path, content, with_bom=True):
    with open(path, 'w', encoding=ENC, newline='') as f:
        if with_bom:
            f.write(BOM)
        f.write(content)


def pending_count(body):
    return len(re.findall(r'^- \[ \]', body, flags=re.MULTILINE))


def main():
    tasks_text, tasks_bom = read_file(SOURCE)
    old_text, old_bom = read_file(ARCHIVE)

    # Locate Блок 16 section
    m16 = re.search(r'^## Блок 16\.[^\n]*$', tasks_text, flags=re.MULTILINE)
    if not m16:
        sys.stderr.buffer.write('No Блок 16 found, nothing to do.\n'.encode('utf-8'))
        return
    # End of block 16: next ^## not "## Блок 16"
    after_16 = re.search(r'^## (?!Блок 16)', tasks_text[m16.end():], flags=re.MULTILINE)
    if after_16:
        block16_end = m16.end() + after_16.start()
    else:
        block16_end = len(tasks_text)
    block16_chunk = tasks_text[m16.start():block16_end]

    # Within block 16, find all `#### Группа X:` headings
    group_pattern = re.compile(r'^(#### Группа [^\n]+)$', flags=re.MULTILINE)
    group_matches = list(group_pattern.finditer(block16_chunk))

    # Determine the end of each group section (until next `^### ` or
    # `^#### ` or end of block16).
    end_pattern = re.compile(r'^(### |#### )', flags=re.MULTILINE)

    closed_groups = []  # (title, body, start_in_block16, end_in_block16)
    for i, gm in enumerate(group_matches):
        body_start = gm.end() + 1  # skip newline after heading
        # Find next heading after this group
        rest = block16_chunk[body_start:]
        next_h = end_pattern.search(rest)
        if next_h:
            body_end = body_start + next_h.start()
        else:
            body_end = len(block16_chunk)
        body = block16_chunk[body_start:body_end]
        if pending_count(body) == 0:
            closed_groups.append((gm.group(1), body, gm.start(), body_end))

    if not closed_groups:
        sys.stderr.buffer.write('No fully-closed groups found in Block 16.\n'.encode('utf-8'))
        return

    # Build new block16 with closed groups replaced by pointers.
    # Walk segments and stitch.
    new_block16 = []
    cursor = 0
    archived_pieces = []  # (heading_chain, body) for OLD_TASKS
    for (title, body, gstart, gend) in closed_groups:
        # Append everything before this group untouched
        new_block16.append(block16_chunk[cursor:gstart])
        # Insert the pointer
        new_block16.append(
            title + '\n\n'
            + '✅ Группа полностью реализована. Подзадачи — '
            + 'см. `OLD_TASKS_RU.md`.\n\n'
        )
        archived_pieces.append((title, body))
        cursor = gend
    new_block16.append(block16_chunk[cursor:])
    new_block16_chunk = ''.join(new_block16)

    # Reassemble tasks_text
    new_tasks = tasks_text[:m16.start()] + new_block16_chunk + tasks_text[block16_end:]

    # Append archived groups to OLD_TASKS_RU.md
    if archived_pieces:
        old_addendum_parts = [
            '\n## Блок 16. Интеграция GUI с реальной логикой — закрытые группы\n\n'
        ]
        for (title, body) in archived_pieces:
            old_addendum_parts.append(title + '\n' + body)
        old_text = old_text.rstrip() + '\n' + ''.join(old_addendum_parts)

    write_file(SOURCE, new_tasks, with_bom=tasks_bom)
    write_file(ARCHIVE, old_text, with_bom=old_bom)

    # Report (use ascii-safe output)
    report_lines = [
        f'TASKS_RU.md: {tasks_text.count(chr(10))} -> {new_tasks.count(chr(10))} lines',
        f'OLD_TASKS_RU.md: {old_text.count(chr(10))} lines',
        f'Archived groups: {len(archived_pieces)}',
    ]
    for (title, _) in archived_pieces:
        report_lines.append(f'  - {title}')
    sys.stderr.buffer.write(('\n'.join(report_lines) + '\n').encode('utf-8'))


if __name__ == '__main__':
    main()
