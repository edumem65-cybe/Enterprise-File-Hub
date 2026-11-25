# معماری

این سند خلاصه‌ی تصمیم‌های اجرایی است. جزئیات هر تصمیم در [ADRها](adr/) آمده است.

## اجزا

| جزء | نقش |
| --- | --- |
| nginx | TLS، routing، مسیر آپلود با محدودیت و timeout جدا، `X-Accel-Redirect` برای دانلود |
| web (Next.js) | UI؛ بدون منطق امنیتی |
| api (NestJS) | auth، مجوز، متادیتا، tus (`@tus/server`)، دانلود، Audit |
| worker | verify، scan، promote، cleanup، retention، reconcile |
| PostgreSQL | منبع حقیقت متادیتا و وضعیت‌ها |
| Redis | فقط صف BullMQ (`noeviction` + AOF)؛ session در PostgreSQL |
| ClamAV | اسکن با path روی volume مشترک |

Docker Compose در نسخه اول؛ بدون Kubernetes.

## چیدمان Storage (روی یک filesystem)

```
STORAGE_ROOT/
  incoming/    # قطعات tus
  quarantine/  # فایل کامل، منتظر/در حال اسکن
  blobs/ab/cd/<blob_key>   # فقط فایل‌های Clean
```

هر سه مسیر باید روی **همان filesystem (همان mount)** باشند تا `rename` اتمیک باشد. هرگز بین دو filesystem rename فرض نشود. مسیر فیزیکی از API پنهان است و نام کاربر هرگز بخشی از مسیر نیست.

## چرخه‌ی آپلود

| گام | upload_sessions.state | file_versions.scan_state | محل فایل |
| --- | --- | --- | --- |
| ایجاد session، رزرو quota | created | - | - |
| دریافت قطعه‌ها | uploading | - | incoming/ |
| بررسی اندازه و sha256 (قفل finalize با idempotency key) | finalizing | - | incoming/ |
| انتقال به قرنطینه (rename) | finalized | quarantined | quarantine/ |
| اسکن | finalized | scanning | quarantine/ |
| موفق | finalized | clean | rename به blobs/، سپس تراکنش DB |
| ردشده (آلوده، نوع ممنوع، خارج از محدوده اسکن) | finalized | rejected | حذف/نگهداری کنترل‌شده |
| خطای اسکن/timeout بعد از retry | finalized | failed | quarantine/ + alert |

قواعد:

- `files.current_version_id` فقط بعد از `clean` و در همان تراکنشی که quota commit می‌شود تغییر می‌کند. نسخه‌ی جدید در قرنطینه، نسخه‌ی Clean قبلی را از Current برنمی‌دارد.
- فایل جدید تا اولین نسخه‌ی Clean در وضعیت `pending` است و در فهرست دیده نمی‌شود.
- Reconcile دوره‌ای: فایل بدون ردیف DB (بعد از N ساعت) حذف می‌شود؛ ردیف DB بدون فایل alert می‌دهد.
- هر job idempotent است؛ اجرای تکراری نسخه یا blob تکراری نمی‌سازد.

## به‌تعویق افتاده از نسخه اول

لینک عمومی، preview/thumbnail، dedup، deny صریح در ACL، جست‌وجوی محتوا، استخراج خودکار آرشیو، ویرایش هم‌زمان اسناد.

## Observability

لاگ ساختاریافته (Pino) بدون secret؛ health/readiness برای DB، Redis، storage و scanner؛ metrics سازگار با Prometheus؛ هشدار ظرفیت در ۷۵٪ (مقدار نهایی با سیاست سازمان).
