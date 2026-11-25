# ADR-0001: tus، ORM و ابزار پایه

**وضعیت:** پذیرفته‌شده (تصمیم پیش‌فرض؛ در صورت وجود دلیل فنی بازبینی شود)

## تصمیم

- **آپلود:** پروتکل tus با `@tus/server` به‌صورت ماژول Upload داخل `apps/api`. hookهای authz روی هر POST/HEAD/PATCH/DELETE؛ datastore سفارشی که روی `FileStorage` می‌نویسد.
- **ORM:** TypeORM با migration دستی SQL (`synchronize` همیشه خاموش). کوئری‌های حساس (quota، ارزیابی ACL) با SQL مستقیم.
- **ابزار:** pnpm workspaces، Node 22+، نسخه‌ها در lockfile قفل.

## قواعد tus

- `Upload-Defer-Length` رد می‌شود (quota reservation به اندازه‌ی مشخص نیاز دارد).
- حداکثر اندازه از policy؛ chunk پیش‌فرض ۸ تا ۱۶ MiB؛ concurrency کم.
- فایل‌های موقت فقط در `incoming/` روی همان filesystem مقصد.

## دلایل و جایگزین‌ها

- `tusd` (Go) کنار گذاشته شد: authz باید با مدل ACL مشترک باشد و سرویس جدا هزینه‌ی عملیاتی دارد. اگر بار IO آپلود روی API مشکل شد، همان کد می‌تواند در instance جدا اجرا شود.
- Prisma کنار گذاشته شد: برای قفل ردیف (`FOR UPDATE`) و ایندکس‌های جزئی باید مدام به raw SQL رجوع می‌کردیم. TypeORM این‌ها را مستقیم پشتیبانی می‌کند و با Nest یکپارچه است.

## پیامد

بار IO آپلود فعلاً روی پروسس API است؛ باید در تست بار (فاز I) اندازه‌گیری شود.
