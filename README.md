# Списки маршрутизации для Shadowrocket

Генератор преобразует списки [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) в текстовые наборы правил Shadowrocket.

| Файл | Содержимое |
| --- | --- |
| `domains.list` | Правила `DOMAIN-SUFFIX` |
| `subnets.list` | Правила `IP-CIDR` и `IP-CIDR6` с `no-resolve` |
| `podkop.list` | Доменные правила, затем IP-правила |

Доменные источники включают Russia inside, Cloudflare, Discord, Google AI, Google Play, H.O.D.C.A, Meta, Telegram и Twitter. Подсети IPv4 и IPv6 берутся из списков Discord, Meta, Telegram и Twitter. Диапазоны провайдеров внутри этих списков сохраняются. Списки подсетей Cloudflare, CloudFront, Hetzner, DigitalOcean и OVH как отдельные источники исключены. Пути к исходным файлам указаны в [update_lists.py](update_lists.py).

## Локальная сборка

Нужен Python 3.11 или новее. Все команды выполняются из каталога проекта. Тесты используют локальные данные.

```sh
python3 -B -m unittest discover -s tests -v
python3 -B update_lists.py
```

Для сборки из локальной копии источника с той же структурой каталогов передайте путь через `--source-dir`. Чтобы записать файлы в другой каталог, добавьте `--output-dir`.

## GitHub Actions

Workflow [Update Shadowrocket lists](.github/workflows/update-lists.yml) запускается в основной ветке ежедневно в 02:23 UTC (05:23 по Москве) и по запросу. Он запускает тесты, скачивает источники и проверяет все записи. Изменения в трёх файлах отправляются одним коммитом. Если содержимое прежнее, запуск завершается без нового коммита. При сбое тестов, загрузки, валидации или отправки предыдущая опубликованная версия остаётся доступна.

После установки [GitHub CLI](https://cli.github.com/) войдите в GitHub и настройте доступ Git по HTTPS:

```sh
gh auth login --web --git-protocol https --scopes workflow
gh auth setup-git
```

Ручной запуск и проверка статуса:

```sh
gh workflow run update-lists.yml --ref main
gh run list --workflow update-lists.yml --event workflow_dispatch --limit 1
```

Подробности запуска доступны через `gh run view RUN_ID`. Ошибку можно посмотреть через `gh run view RUN_ID --log-failed`. После исправления причины повторите обычный ручной запуск.

## Shadowrocket

Секция `[Rule]` для режима **Config**. Если прокси-политика в вашем профиле называется иначе, подставьте её имя вместо `PROXY`.

```ini
[Rule]
DOMAIN,raw.githubusercontent.com,DIRECT
RULE-SET,https://raw.githubusercontent.com/Faenno/shadowrocket-routing-public/main/podkop.list,PROXY
FINAL,DIRECT
```

После сохранения профиля обновите `podkop.list` в Shadowrocket и проверьте сопоставление правил в журнале соединений.
