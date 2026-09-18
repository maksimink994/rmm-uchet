# РММ Учёт — Cloudflare online v0.4

Cloudflare Worker + D1 + PWA. Общая база для нескольких устройств и пользователей.

## Перед первым Deploy
1. Cloudflare → Storage & databases → D1 → Create database: `rmm-uchet-db`.
2. Открыть D1 Console и выполнить содержимое `schema.sql`.
3. Скопировать Database ID и заменить `REPLACE_WITH_D1_DATABASE_ID` в `wrangler.jsonc`.
4. GitHub/Cloudflare Build command: `npm install`; Deploy command: `npx wrangler deploy`.

После Deploy открыть workers.dev адрес и создать главного администратора.

`public/legacy.html` — сохранённый интерфейс v0.2.6. В v0.4 он включён для визуального теста; перенос всех его операций с localStorage на D1 — следующий этап.
