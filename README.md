# Enterprise File Hub

سامانه آپلود و مدیریت فایل سازمانی: آپلود قابل ادامه (tus)، قرنطینه و اسکن امنیتی، کنترل دسترسی سازمانی (RBAC + ACL)، نسخه‌بندی، اشتراک‌گذاری و Audit.

> **وضعیت: فاز B (Foundation).** هنوز کد برنامه‌ای نوشته نشده. این شاخه تصمیم‌های معماری (ADR)، طرح اولیه دیتابیس، ساختار monorepo و محیط توسعه را اضافه می‌کند.

## ساختار مخزن

| مسیر | محتوا |
| --- | --- |
| `apps/web` | Next.js + TypeScript (UI کاربر و پنل مدیر) |
| `apps/api` | NestJS: auth، سازمان، پوشه/فایل، آپلود، دانلود، Audit |
| `apps/worker` | Workerها: scan، hash، cleanup، retention |
| `packages/contracts` | DTO و schema مشترک، error codeها |
| `infra/compose` | Docker Compose، reverse proxy |
| `docs` | معماری، ADR، مدل داده، نقشه راه، پرسش‌های باز |

## شروع سریع (محیط توسعه)

1. `cp .env.example .env` و مقادیر placeholder را عوض کنید (فایل `.env` هرگز commit نمی‌شود).
2. اجرای سرویس‌های پایه: `pnpm compose:up` (PostgreSQL، Redis، ClamAV، Keycloak برای توسعه).
3. توقف: `pnpm compose:down`.

پورت‌ها فقط روی `127.0.0.1` باز می‌شوند.

## مستندات

- [معماری](docs/architecture.md)
- [ADRها](docs/adr/)
- [نقشه راه و معیار خروج هر فاز](docs/roadmap.md)
- [پرسش‌های باز (نیاز به تصمیم سازمان)](docs/open-questions.md)
- [طرح اولیه دیتابیس](apps/api/db/migrations/0001_init.sql)

## اصول

- قواعد امنیتی و دسترسی فقط در Backend اعمال می‌شود؛ UI فقط تجربه کاربری است.
- هیچ secret ای (رمز، کلید، توکن) در Git قرار نمی‌گیرد.
- فایل تا نتیجه‌ی اسکن Clean قابل دانلود نیست؛ هر خطای اسکن به معنی رد است (fail closed).
- هر تغییر روی زیرساخت Production با تأیید مسئول زیرساخت و برنامه بازگشت انجام می‌شود.
