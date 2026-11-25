# نقشه راه توسعه

هر فاز با «معیار خروج» بسته می‌شود. زمان‌بندی بعد از مشخص شدن اندازه‌ی تیم و بسته شدن [پرسش‌های باز](open-questions.md) تعیین می‌شود.

| فاز | محتوا | معیار خروج |
| --- | --- | --- |
| A. Discovery/ADR | نیازمندی‌ها، permission matrix، سیاست فایل، quota، retention، ERD، threat model | سند نیازمندی و پرسش‌های باز تأییدشده |
| B. Foundation (فعلی) | monorepo، lint/typecheck، env validation، Docker dev، migration، health، CI، OpenAPI | `pnpm compose:up` و health endpointها کار می‌کنند؛ CI سبز |
| C. Identity & Org | OIDC، session، کاربران/واحدها/گروه‌ها، RBAC و ارزیابی ACL | تست منفی scope و privilege boundary سبز |
| D. Storage & Upload | FileStorage، tus، quota، resume، finalize، checksum | آپلود ۱ GB با قطع شبکه و restart ادامه می‌یابد؛ orphan reconcile |
| E. Quarantine & Scan | صف، ClamAV، MIME/magic، state machine، publish اتمیک | EICAR رد می‌شود؛ scanner خاموش = fail closed |
| F. File Management | فهرست، جست‌وجوی نام (pg_trgm)، rename/move، دانلود، Trash، نسخه‌ها | تست مجوز روی همه‌ی عملیات |
| G. Sharing & Admin | share کاربر/گروه، expiry/revoke، quota/policy، جست‌وجوی Audit | revoke بلافاصله اثر می‌کند |
| H. Frontend Polish | RTL، upload queue، خطاها، accessibility | تست کاربران پایلوت |
| I. Hardening & Recovery | تست امنیت/بار/پایداری، Veeam restore (VM/DB/فایل)، runbook | بدون blocker؛ sign-off |
| J. Pilot/Production | پایلوت یک واحد، انتقال فایل با hash، آموزش | انتشار رسمی |

## معیارهای عددی پیشنهادی (قابل بازبینی)

- آپلود فایل ۵ GB: مصرف RAM پروسس API ثابت و کمتر از ۵۰۰ MB بالاتر از baseline.
- ۱۰ آپلود هم‌زمان ۱ GB بدون خطا و بدون عبور از quota.
- بعد از restart کامل سرویس‌ها، آپلودهای ناتمام از آخرین offset معتبر ادامه می‌یابند.
