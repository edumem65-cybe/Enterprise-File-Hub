# ADR-0002: احراز هویت و session

**وضعیت:** پذیرفته‌شده (منبع هویت نهایی در [پرسش‌های باز](../open-questions.md))

## تصمیم

- احراز هویت فقط از طریق **OIDC** (کتابخانه‌ی `openid-client`). در توسعه Keycloak؛ در Production هر IdP سازمان (مثلاً AD FS یا Keycloak با LDAP federation).
- حساب محلی ساخته نمی‌شود مگر IdP در دسترس نباشد و سازمان صریح تأیید کند.
- Session سمت سرور (جدول `sessions` در PostgreSQL)، cookie با `HttpOnly`، `Secure`، `SameSite=Lax`، و refresh rotation. توکن در `localStorage` ذخیره نمی‌شود.
- web و api پشت یک origin (nginx). CORS با allowlist.
- **CSRF:** هدر سفارشی برای همه‌ی درخواست‌های غیر GET، از جمله PATCH/POST/DELETE مربوط به tus.
- گروه‌ها از claim یا sync دوره‌ای IdP می‌آیند؛ حداکثر تأخیر مجاز عضویت گروه یک تصمیم باز سازمانی است. مجوزهای گروهی در لحظه‌ی دسترسی ارزیابی می‌شوند و cache ACL با تغییر عضویت invalidate می‌شود.

## پیامد

با انتزاع OIDC، تغییر IdP بدون بازنویسی ممکن است. MFA در لایه‌ی IdP اعمال می‌شود.
