# Установка без вопросов

[English](../en/unattended-install.md) · **Русский**

Ставьте NetRuleRouter сценарием, вместе с другими программами, и сразу со
своими правилами для каждого пользователя компьютера. Во время установки
ничего не спрашивается, а файл правил, который нельзя использовать, проваливает
установку, а не оставляет компьютер настроенным наполовину.

## Windows

Через MSI:

```
msiexec /i NetRuleRouter.msi /qn /l*v C:\temp\nrr-setup.log ^
  PROVISION=C:\deploy\rules_primary.txt ^
  PROVISION_SECONDARY=C:\deploy\rules_secondary.txt ^
  PROVISION_SETTINGS=C:\deploy\settings.yaml ^
  SECONDARY_UNSET=direct
```

Установщик EXE принимает те же имена как ключи:

```
NetRuleRouter-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /LOG=C:\temp\nrr-setup.log ^
  /PROVISION=C:\deploy\rules_primary.txt /SECONDARY_UNSET=direct
```

| Параметр | Что даёт |
|---|---|
| `PROVISION` | Правила основного подключения |
| `PROVISION_SECONDARY` | Правила дополнительного подключения |
| `PROVISION_SETTINGS` | Файл настроек, выгруженный на другом компьютере: его режим маршрутизации становится начальным. Подключения из него не переносятся — у каждого компьютера они свои |
| `SECONDARY_UNSET` | `direct` (по умолчанию): пока дополнительное подключение не выбрано, его правила идут напрямую. `block`: до выбора они удерживаются |

Пути указывайте полные. Любой параметр можно не задавать.

## Linux

Перед установкой `.deb` или `.rpm` положите файлы в
`/etc/netrulerouter/provision/` (владелец — root): `rules_primary.txt`,
`rules_secondary.txt`, `settings.yaml` и `options.conf` со строкой
`secondary-unset = direct` или `secondary-unset = block`. Служба заберёт их при
первом запуске.

Из архива — передайте файлы установщику:

```
sudo ./install.sh --provision rules_primary.txt --provision-secondary rules_secondary.txt \
  --provision-settings settings.yaml --secondary-unset block
```

## Что происходит после установки

- Правила становятся общими правилами, с которых начинает каждый пользователь
  компьютера. Пользователь, который потом правит свои правила, сохраняет свои
  правки; общие правила остаются теми, что вы поставили.
- Пока пользователь не подтвердит основное подключение, сеть работает так, как
  будто программы нет. Трей предлагает подключение компьютера к интернету —
  подтвердить одним нажатием или выбрать другое.
- Файлы применяются один раз. После этого они остаются, переименованные, в
  папке подготовки службы (`%ProgramData%\NetRuleRouter\provision` на Windows,
  `/etc/netrulerouter/provision` на Linux) — видно, что они взяты.

## Когда файл нельзя использовать

Файлы проверяются до того, как что-то будет установлено. Файл, который нельзя
использовать, проваливает установку, а причина — в журнале установки:

| Код | Что не так |
|---|---|
| 10 | Правила основного подключения |
| 11 | Правила дополнительного подключения |
| 12 | Файл настроек |
| 13 | Значение `SECONDARY_UNSET` |
| 14 | Файлы не удалось подготовить для службы |

MSI при этом возвращает 1603, установщик EXE — 7, а `install.sh` — код из
таблицы. Проверить файлы заранее можно командой
`nrr-service provision-check --primary <файл>` на Windows или
`nrr-serviced provision-check --primary <файл>` на Linux: она ничего не меняет и
возвращает те же коды.

## См. также

- [Формат файла правил](rules-file-format.md)
- [Сборка пакетов для Windows](packaging-windows.md) и [для Linux](packaging-linux.md)
- [Несколько пользователей на одном компьютере](several-users.md)
