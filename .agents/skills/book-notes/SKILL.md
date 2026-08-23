---
name: book-notes
description: How and when to write architectural decision notes in notes/ for the future Rust book. Invoke after any non-trivial design decision with a real trade-off.
---

# Book Notes (notes/)

`notes/` is a local-only folder (gitignored) for recording architectural decisions that will be useful for a future book about building real-world Rust applications.

**HARD RULE — route the note to the right folder before writing it.** The root
of `notes/` is the engineering journal (architectural decisions, book material)
and is what the rest of this skill describes. Route by the question the note
answers:

| question | folder | format |
|---|---|---|
| why is the code like this | root | this skill |
| what do we say about it publicly, and to whom | `produkt/` | `produkt/README.md` |
| how do we intend to build it | `dizayn/` | `dizayn/README.md` |
| why are we NOT doing it | `idei/` | `idei/README.md` |
| what we believed that turned out false | `arhiv/` | `arhiv/README.md` |

A single file is never two of these: an article teardown goes to `produkt/`, and
any code decision it triggered becomes its own note in the root. The indexer
walks the root and `arhiv/` only, so notes in `produkt/`, `dizayn/` and `idei/`
get no `NRR-*` id by design — cite them by filename.

**When to write a note:** after any non-trivial decision — choosing between two approaches, discovering a platform-specific constraint, hitting a compiler limitation that forced a design change, or finding that an "obvious" solution failed. If there was a real trade-off, it belongs here. Write proactively whenever a decision has real educational value — don't wait to be asked.

**HARD RULE — extend before creating (applies to every agent writing notes).** Before creating a new note, scan existing filenames in `notes/` (and grep their `## Решение:` headers) for the same theme. If a note on the theme exists, EXTEND or amend that note (add a dated section, refine the lesson, add the new example) instead of creating a near-duplicate file. Create a new file only for a genuinely new decision/theme. One theme = one evolving note.

**Language: Russian.** File naming: `YYYY-MM-DD_короткое-описание.md`.

**HARD RULE — every note starts with a status header.** `notes/` is the project's monetizable know-how, so a reader must be able to tell a proven fact from an engineering guess, and a live decision from a superseded one. Put this block at the very top of the file, before the title:

```
---
id: NRR-TBD
статус: актуально
доказано: тест
доказательство: <path/to/test.rs::test_name — обязательно для «тест»>
линия: <одна из линий в notes/INDEX.md; новая только для реально новой темы>
проверено: YYYY-MM-DD
---
```

- `статус`: `актуально` (так работает сейчас) | `заменено` (+ поле `заменено-на:`) | `историческое` (осознанно пройденный этап) | `ошибочно` (утверждение оказалось неверным) | `требует-решения` (+ поле `вопрос:`).
- `доказано`: `тест` | `железо` (подтверждено на HW-прогоне) | `наблюдение` (видели, механизм не доказан) | `предположение` (+ обязательное поле `опровергается: <какой опыт это опровергнет>`).
- `id` проставляет скрипт: `python notes/tools/notes_index.py` присваивает номера и пересобирает `INDEX.md` из шапок. Индекс — производное; идентичность живёт в файле.

**Никогда не переписывай устаревшую заметку задним числом.** Ценность журнала — траектория: меняй статус, добавляй `заменено-на:` и раздел `**Статус на YYYY-MM-DD:**` в конце (что изменилось, где живёт текущее поведение). Объективные фактические ошибки (неверная константа, устаревшее имя) правятся в тексте с пометкой `**Факт-чек YYYY-MM-DD:**`.

**Required sections per note:**
- `## Решение:` — название решения
- `**Контекст:**` — задача и варианты которые рассматривались
- `**Выбор:**` — что выбрали и почему
- `**Отвергнутые альтернативы:**` — почему не подошли
- `**Урок для книги:**` — суть, которую читатель должен вынести
- `**Теги:**` — из набора: `#rust #ipc #sqlite #windows #linux #macos #qt #архитектура #тестирование #ffi #async #ownership #traits #unsafe`
