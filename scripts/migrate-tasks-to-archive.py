#!/usr/bin/env python3
"""One-shot migration of closed blocks from TASKS_RU.md into OLD_TASKS_RU.md.

Strategy:
  * Identify each top-level block (## Блок N. Title).
  * For each block: if zero `- [ ]` items inside → archive whole block.
  * For block 16: identify sub-blocks (### Подблок 16.N.) and archive
    each closed one individually. 16.QoL+ section stays in TASKS_RU.md.
  * Replace archived sections with a one-line "✅ Реализован — детали в
    OLD_TASKS_RU.md" pointer.

Encoding: explicit UTF-8 with BOM (matches source). Never use Bash
tools that might mangle Cyrillic on Windows.
"""

import re
import sys

ENC = 'utf-8'
BOM = '﻿'

SOURCE = 'TASKS_RU.md'
ARCHIVE = 'OLD_TASKS_RU.md'


def read_source():
    with open(SOURCE, 'r', encoding=ENC) as f:
        text = f.read()
    if text.startswith(BOM):
        text = text[1:]
    return text


def write_with_bom(path, content):
    with open(path, 'w', encoding=ENC, newline='') as f:
        f.write(BOM + content)


def split_top_blocks(text):
    """Return [(prefix_or_block_title, body)] in order.

    First element is the file preamble before any ## heading.
    Subsequent elements are (heading_line, body_until_next_heading).
    """
    pattern = re.compile(r'^(## [^\n]+)$', flags=re.MULTILINE)
    parts = []
    last_end = 0
    last_title = None
    for m in pattern.finditer(text):
        if last_title is None:
            parts.append(('__PREAMBLE__', text[last_end:m.start()]))
        else:
            parts.append((last_title, text[last_end:m.start()]))
        last_title = m.group(1)
        last_end = m.end() + 1  # skip the newline after heading
    # final tail
    if last_title is None:
        parts.append(('__PREAMBLE__', text[last_end:]))
    else:
        parts.append((last_title, text[last_end:]))
    return parts


def split_sub_blocks(body):
    """Split a top-block body by '### ' sub-headings.

    Returns [(prefix_or_subheading, content)].
    """
    pattern = re.compile(r'^(### [^\n]+)$', flags=re.MULTILINE)
    parts = []
    last_end = 0
    last_title = None
    for m in pattern.finditer(body):
        if last_title is None:
            parts.append(('__PREFIX__', body[last_end:m.start()]))
        else:
            parts.append((last_title, body[last_end:m.start()]))
        last_title = m.group(1)
        last_end = m.end() + 1
    if last_title is None:
        parts.append(('__PREFIX__', body[last_end:]))
    else:
        parts.append((last_title, body[last_end:]))
    return parts


def pending_count(body):
    return len(re.findall(r'^- \[ \]', body, flags=re.MULTILINE))


def done_count(body):
    return len(re.findall(r'^- \[x\]', body, flags=re.MULTILINE))


# Blocks fully archived (whole block moves)
FULL_ARCHIVE_BLOCKS = {
    '## Блок 1. Инициализация проекта и базовая структура',
    '## Блок 4. Security-модель и доверенные границы',
    '## Блок 8. Импорт, review и внешние изменения',
    '## Блок 13.R-GUI. Рефактор подсистемы запуска GUI/tray',
}


def is_full_archive_block(title):
    return title in FULL_ARCHIVE_BLOCKS


def is_block_16(title):
    return title == '## Блок 16. Интеграция GUI с реальной логикой'


def archive_sub_blocks_in_block16(body):
    """For block 16: archive each ### Подблок 16.N where pending == 0.

    Keep the active subsections (16.QoL+, anything still open) and
    the block's preamble (status summary). Returns (new_body, archived_chunks).
    """
    sub_parts = split_sub_blocks(body)
    new_parts = []
    archived = []  # list of (subheading, content)
    for (title, content) in sub_parts:
        if title == '__PREFIX__':
            new_parts.append(content)
            continue
        # Heuristic: archive only sub-blocks named "### Подблок 16.X." where
        # X is a number AND content has zero `- [ ]`. The QoL+ phase
        # headers ("#### 16.QoL+1. ...") live inside another sub-block
        # and won't match here. Safe.
        is_numbered_sub = re.match(r'^### Подблок 16\.\d', title) is not None
        pend = pending_count(content)
        if is_numbered_sub and pend == 0:
            archived.append((title, content))
            # Replace with one-line pointer.
            new_parts.append(
                title + '\n\n'
                + '✅ Реализован. Полные подзадачи и acceptance — '
                + 'см. `OLD_TASKS_RU.md`.\n\n'
            )
        else:
            new_parts.append(title + '\n' + content)
    return ''.join(new_parts), archived


def main():
    text = read_source()
    parts = split_top_blocks(text)

    new_pieces = []
    archived_pieces = []  # ordered list of (heading_chain, body) for archive

    for (title, body) in parts:
        if title == '__PREAMBLE__':
            new_pieces.append(body)
            continue

        if is_full_archive_block(title):
            # Whole block moves; leave a one-liner pointer.
            archived_pieces.append((title, body))
            new_pieces.append(
                title + '\n\n'
                + '✅ Реализован. Полные подзадачи и acceptance — '
                + 'см. `OLD_TASKS_RU.md`.\n\n'
            )
        elif is_block_16(title):
            # Mixed: archive closed numbered sub-blocks, keep the rest.
            new_body, archived_subs = archive_sub_blocks_in_block16(body)
            new_pieces.append(title + '\n' + new_body)
            for (sub_title, sub_content) in archived_subs:
                archived_pieces.append((title + ' → ' + sub_title, sub_content))
        else:
            # Partial blocks: leave untouched in this pass.
            new_pieces.append(title + '\n' + body)

    new_tasks = ''.join(new_pieces)

    # Build OLD_TASKS_RU.md content
    archive_header = (
        '# OLD_TASKS_RU.md — архив завершённых задач\n\n'
        '> **Этот файл — историческая запись.** Активные задачи живут\n'
        '> в `TASKS_RU.md`. Сюда смотрят, чтобы вспомнить «почему мы\n'
        '> решили X в марте» или «как закрывали блок 12». Грепом ищите\n'
        '> по названию блока: `## Блок 1.`, `## Блок 16.` → `### Подблок 16.9.`\n'
        '> и т.д.\n'
        '>\n'
        '> Источник истины для архитектурных инвариантов — auto-memory\n'
        '> `~/.claude/projects/.../memory/MEMORY.md` (быстрее парсится).\n'
        '\n'
    )

    # Group archived pieces by parent
    archive_body_parts = []
    current_parent = None
    for (heading_chain, content) in archived_pieces:
        if ' → ' in heading_chain:
            parent, sub = heading_chain.split(' → ', 1)
            if parent != current_parent:
                archive_body_parts.append(parent + '\n')
                current_parent = parent
            archive_body_parts.append(sub + '\n' + content)
        else:
            archive_body_parts.append(heading_chain + '\n' + content)
            current_parent = heading_chain

    archive_content = archive_header + ''.join(archive_body_parts)

    # Write
    write_with_bom(SOURCE, new_tasks)
    write_with_bom(ARCHIVE, archive_content)

    # Report
    print(f'TASKS_RU.md: {text.count(chr(10))} → {new_tasks.count(chr(10))} lines')
    print(f'OLD_TASKS_RU.md: {archive_content.count(chr(10))} lines')
    print(f'Archived: {len(archived_pieces)} sections')
    for (heading, _) in archived_pieces:
        print(f'  - {heading}')


if __name__ == '__main__':
    main()
