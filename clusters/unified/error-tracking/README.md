# GlitchTip

Два web и два worker на разных VPS, PostgreSQL HA и отдельный Garage bucket.
Образ `glitchtip/glitchtip:6.2.6` закреплён digest; очереди, кеш и сессии хранятся
в PostgreSQL. Valkey не нужен. Это конфигурация развёртывания, а не свидетельство
успешного запуска: после каждого обновления нужны проверки ниже.

## Зависимости и первая установка

В namespace `error-tracking` bootstrap создаёт Secret `glitchtip-runtime`:

| Ключ | Назначение |
|---|---|
| `DATABASE_URL` | DB/роль `glitchtip`, host `unified-postgres.database.svc`, порт 5432; `sslmode=verify-full&sslrootcert=/etc/postgresql/ca.crt&connect_timeout=5` |
| `ca.crt` | CA PostgreSQL, монтируется read-only |
| `SECRET_KEY` | Постоянный случайный Django key; сохраняется в зашифрованном backup |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Права чтения/записи только отдельного bucket |
| `AWS_STORAGE_BUCKET_NAME`, `AWS_S3_ENDPOINT_URL` | Bucket `glitchtip`, внутренний Garage Service |

Отдельный Secret `glitchtip-bootstrap-admin` содержит `email` и `password`.
Он доступен только migration Job. Ожидаемый email указан в `settings.env`;
пароль — случайный, не короче 24 символов. Секреты, DSN и вывод с ними не коммитить.
DB owner нужен для схемы, расширений и partition maintenance; роль без superuser,
CREATEDB/CREATEROLE/REPLICATION, лимит 32 соединения. DB pool 6 на процесс,
для init/Job 2. Лимиты памяти: web 768 Mi и worker 1 Gi; steady requests всей группы
400m CPU/1280 Mi RAM, распределённые поровну между VPS. Это начальный бюджет,
фактические пики, очереди и запас при потере одной VPS проверяются отдельно.

1. Подготовить DB/Secrets/bucket, проверить права, свободное место и актуальный
   backup PostgreSQL. Bucket ограничить 1 GiB/100000 объектов. Включить его в backup.
2. Применить **основной** каталог. Init обеих Deployments ждёт миграций и первого
   активного администратора; до этого web вообще не начинает слушать.
3. Явно создать migration Job, исключённый из обычной Flux reconciliation:

   ```sh
   kubectl create -f clusters/unified/error-tracking/migration-job.yaml
   kubectl -n error-tracking wait --for=condition=complete job/glitchtip-migrate-6-2-6 --timeout=900s
   ```

   Job выполняет штатные migrate/createcachetable/maintain_partitions, создаёт
   таблицу capacity guard, затем администратора, организацию `unified`, команду
   `apps` и проект `platform-canary`. Advisory transaction lock исключает
   параллельную миграцию. При существующих пользователях пароль не меняется:
   проверяется только ожидаемый активный superuser. Ошибка или неизвестный исход
   требуют чтения состояния; Job автоматически не повторяется и не удаляется.
4. Дождаться 2/2 web и 2/2 worker, успешного guard Job и `/metrics`. Выполнить
   контролируемые проверки из одного web Pod:

   ```sh
   kubectl -n error-tracking exec deployment/glitchtip-web -- python /opt/infra/storage_check.py
   kubectl -n error-tracking exec deployment/glitchtip-web -- python /opt/infra/canary.py
   ```

   Первая проверяет реальный Django S3 backend небольшим собственным объектом
   write/read/delete; при ошибке объект сохраняется для разбора. Вторая отправляет
   исключение штатным Sentry SDK через локальный HTTP и проверяет его обработку
   worker и запись в DB. Она не доказывает доступность публичного ingress.
5. Через приватный port-forward проверить вход администратора, проект и событие
   в UI. Проверить, что регистрация нового постороннего пользователя запрещена.
6. Только после этого включить `public/` отдельным ресурсом Flux. Issuer
   `letsencrypt-production` и Traefik должны быть готовы; HTTP01 port 8089
   разрешён отдельной NetworkPolicy. Проверить публичную цепочку TLS, вход,
   отправку canary через публичный DSN и видимость issue под авторизованной сессией.

Upstream `ENABLE_USER_REGISTRATION=false` разрешает самого первого пользователя:
поэтому приватный bootstrap и init gate обязательны и при восстановлении с нуля.
В обычных web/worker нет admin credentials, ServiceAccount token или внешнего
доступа в интернет. `/admin` и `/metrics` закрыты на публичном ingress. Проверить
403 для `/metrics`, `/metrics/`, query, encoded path/slash и аналогично `/admin`;
исключить возможный обход до публикации. Prometheus читает Pod напрямую.

## Приём ошибок и ограничения

Приложения используют обычный Sentry SDK с DSN своего проекта. Создавать отдельный
проект на приложение; DSN даёт только возможность отправки, а не чтения ошибок.

В интерфейсе `https://errors.apps.shanginn.io` открыть организацию `unified`,
создать проект приложения и скопировать его DSN из настроек проекта. Передавать
его через runtime Secret/переменную `SENTRY_DSN`, а не коммитить в Git. Проект
`platform-canary` предназначен для проверки платформы. Существующие приложения
не начинают отправлять ошибки автоматически: SDK подключается в их исходниках.

Пример Python с установленным `sentry-sdk`:

```python
import os
import sentry_sdk

sentry_sdk.init(
    dsn=os.environ["SENTRY_DSN"],
    environment=os.environ.get("APP_ENV", "production"),
    release=os.environ.get("APP_RELEASE"),
    send_default_pii=False,
    traces_sample_rate=0.0,
)
```

Пример Node.js с `@sentry/node`, выполняемый до импорта приложения:

```javascript
import * as Sentry from "@sentry/node";

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.APP_ENV ?? "production",
  release: process.env.APP_RELEASE,
  sendDefaultPii: false,
  tracesSampleRate: 0,
});
```

Для браузера использовать соответствующий Sentry SDK и публичный HTTPS DSN;
не передавать в frontend пароль администратора или API token. Сначала отправить
одно искусственное исключение и проверить issue в нужном проекте. Для метрик
приложения отдельно включить [Prometheus opt-in](../monitoring/README.md).

Начать с `send_default_pii=false`, tracing выключен или с малой выборкой;
session replay/profiling/Sentry-specific features не считать поддержанными без
отдельной проверки. Логи и uptime GlitchTip выключены, их собирает общий стек.
Никаких внешних Sentry DSN или телеметрии не настроено; egress ограничен DNS,
PostgreSQL и Garage. Server-side scrub фильтрует ключи/карты/privatekeys/email,
но не гарантирует удаление любой чувствительной строки из исключения.

SMTP пока выключен. Приём ошибок и UI работают без почты; email alerts,
приглашения и сброс пароля не считаются работающими. Для SMTP нужны отдельные
Secret/settings и разрешённый egress к согласованному серверу, затем реальная
проверка доставки. Не использовать console/file email backend в production.

Ingress ограничивает только ingestion маршруты: 1 request/s на IP с burst 20,
5 request/s на Host с burst 20,10 одновременных запросов и 256 KiB request body.
Лимиты локальны каждому из двух Traefik: совокупный предел вдвое выше.
Envelope может содержать несколько событий; это лимит запросов, не событий.
UI/login/static не получают этот низкий лимит. Decompressed body также 256 KiB;
artifact unzip 64 MiB/1000 файлов. Пакеты больше лимита будут отклоняться;
настройки увеличивать только вместе с измерением памяти/скорости роста DB.

Хранение ошибок/транзакций/файлов/релизов 7 дней. Ротация выполняется worker;
она не ограничивает размер DB. Раз в минуту capacity guard измеряет dedicated
DB и при 2 GiB атомарно защёлкивает запрет приёма **всех** её организаций.
Он не удаляет события и никогда не открывает приём автоматически. Созданная
после срабатывания организация закрывается следующим успешным запуском guard.
При отключении guard защита не сработает — его устаревшие метрики требуют alert.

2 GiB — мягкий порог: очередь, индексы, WAL, запросы между запусками и недоступный
scheduler дают превышение. Он не заменяет контроль диска/PostgreSQL WAL и не
является filesystem quota. Даже после удаления событий физический размер DB
может не уменьшиться сразу. Сначала выяснить причину, проверить backlog/retention
и backup; возвращать приём только отдельной проверенной транзакцией оператора.
`ProjectKey.rate_limit_*` upstream пока не реализованы; billing quota в обычном
self-hosted режиме отключена и здесь не используется.

## Мониторинг и обновления

Web `/metrics`: стандартные Django/HTTP metrics и
`glitchtip_capacity_guard_{last_success_timestamp_seconds,latched,database_bytes,threshold_bytes,closed_organizations}`.
На обоих web доступны одинаковые DB-level guard gauges — не суммировать размер.
Alert: нет успешного guard 180s, latch 1, DB 1 GiB warning/1.5 GiB critical.
Worker порт 9000 `/metrics`: `vtasks_queue_depth{queue}`, `vtasks_active_tasks`,
`vtasks_tasks_processed_total{task_name,queue,status}` и latency histogram.
Следить за ошибками/ростом очереди и отсутствием обоих worker; Ready heartbeat
подтверждает живой event loop, а обработку данных доказывает canary.
Web `/_health/` проверяет процесс; readiness `/metrics` также обращается к DB.

Для обновления сначала backup+restore check, review upstream changelog/schema,
затем новая версия Job и image digest. Стабильные ConfigMap имена нужны явному
Job: при изменении settings/scripts увеличить `config-revision` в Deployments.
RollingUpdate без surge и hard anti-affinity меняет по одному web/worker;
PDB сохраняет по одному экземпляру при добровольных disruptions.
PostgreSQL async: failover может потерять последние подтверждённые события/задачи.
S3 RF3 и бэкапы не превращают асинхронную DB репликацию в синхронную.

Источники: [установка](https://glitchtip.com/documentation/install/),
[6.2.6 source/changelog](https://gitlab.com/glitchtip/glitchtip-backend/-/blob/v6.2.6/CHANGELOG),
[SDK](https://glitchtip.com/sdkdocs/),
[native PostgreSQL TLS](https://gitlab.com/glitchtip/django-vpg/-/blob/v0.4.0/README.md).
