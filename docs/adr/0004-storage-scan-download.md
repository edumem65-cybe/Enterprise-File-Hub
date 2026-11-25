# ADR-0004: ذخیره‌سازی، اسکن و دانلود

**وضعیت:** پذیرفته‌شده

## ذخیره‌سازی و publish اتمیک

- `incoming/`، `quarantine/` و `blobs/` روی **یک filesystem** (دیسک داده‌ی SAN-backed). انتقال بین مراحل با `rename` در همان filesystem؛ قبل از rename نهایی `fsync` فایل.
- `blob_key` تصادفی است و مسیر shard شده (`ab/cd/<key>`). یک blob برای هر نسخه؛ بدون dedup.
- اینترفیس `FileStorage` مسیر فیزیکی را پنهان می‌کند؛ implementation اول: filesystem محلی.

## اسکن

- ClamAV با دستور اسکن **path** روی volume مشترک (فقط خواندنی)، نه INSTREAM، تا سقف stream مطرح نشود. `MaxFileSize` و `MaxScanSize` در `clamd.conf` برابر یا بیشتر از سقف رسمی آپلود تنظیم شود.
- فایل خارج از محدوده‌ی اسکن، رمزدار، آلوده یا نوع غیرمجاز: `rejected` با دلیل ثبت‌شده.
- خطا یا timeout: retry محدود با backoff؛ بعد از آن `failed` + alert. هرگز به معنی Clean نیست (fail closed).
- اعتبارسنجی extension، MIME و magic bytes باهم؛ allowlist نوع فایل با سازمان؛ استخراج خودکار آرشیو در نسخه اول نیست.
- `freshclam` و سلامت signatureها پایش می‌شود.

## دانلود

- API مجوز را در لحظه بررسی و audit ثبت می‌کند، سپس nginx بایت‌ها را با `X-Accel-Redirect` می‌فرستد (location داخلی)؛ Node جریان فایل را پروکسی نمی‌کند و Range پشتیبانی می‌شود.
- هدرها: `Content-Disposition: attachment` با `filename*` (RFC 5987) برای نام فارسی، `X-Content-Type-Options: nosniff`، و CSP محدود.
- نسخه اول فقط `attachment` است (برای جلوگیری از stored XSS با HTML/SVG)؛ نمایش inline و preview بعداً و فقط برای allowlist امن، ترجیحاً از دامنه‌ی جدا.
- دانلود فایل Quarantine/Rejected ممنوع است.

## پیامد

فایل سه بار خوانده می‌شود (hash، scan، احتمالاً verify)؛ ظرفیت IO در تست بار سنجیده شود. دیسک Temp باید برای آپلود هم‌زمان فایل‌های بزرگ سایز شود.
