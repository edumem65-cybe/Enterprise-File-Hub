# قرارداد API (پیش‌نویس)

پیشوند `/api/v1`. خطاها به‌صورت `application/problem+json` با فیلد `code` پایدار؛ لیست‌ها با cursor pagination؛ عملیات حساس با هدر `Idempotency-Key`. نسخه‌ی نهایی به‌صورت OpenAPI در `packages/contracts` تولید می‌شود. همه‌ی پاسخ‌ها قبل از ارسال با محدوده‌ی دید نقش فیلتر می‌شوند (ADR-0006).

| بخش | Endpointها | دسترسی |
| --- | --- | --- |
| Auth | `POST /auth/login`، `POST /auth/logout`، `GET /auth/me`، `POST /auth/change-password` | عمومی/واردشده |
| Users | `GET/POST /users`، `GET/PATCH /users/:id`، `POST /users/:id/disable`، `POST /users/import` (CSV) | مدیر ارشد: همه؛ مدیر منطقه: زیرمجموعه |
| Quota | `GET /users/:id/usage`، `PATCH /users/:id/quota`، `GET/POST /quota-profiles` | مدیران (در محدوده) |
| Org units | `GET/POST/PATCH /org-units` | مدیر ارشد نوشتن، همه خواندن |
| Folders | `GET/POST /folders`، `PATCH /folders/:id` (نام/انتقال)، `DELETE /folders/:id`، `GET/PUT /folders/:id/acl` | مالک/مجوز |
| Files | `GET /folders/:id/files`، `GET /files/:id`، `PATCH /files/:id`، `DELETE /files/:id`، `GET /files/search?q=` | مالک/مجوز/مدیر |
| Uploads | `POST /uploads` (ایجاد نشست + quota + توکن)، tus روی `/files-upload/*`، `POST /uploads/:id/finalize`، `GET /uploads?state=active` (بازیابی بعد از Refresh)، `DELETE /uploads/:id` | کاربر (مالک نشست) |
| Download | `POST /files/:id/versions/:v/download-token` (بررسی مجوز + Audit)، دانلود با توکن کوتاه‌عمر روی `/files-download/*` | مجوز DOWNLOAD |
| Versions | `GET /files/:id/versions`، `POST /files/:id/versions/:v/restore` (نسخه‌ی جدید می‌سازد) | MANAGE_VERSIONS |
| Trash | `GET /trash`، `POST /trash/:id/restore`، `DELETE /trash/:id` (حذف دائمی طبق سیاست؛ با دلیل) | مالک/مدیر |
| Shares | `POST /shares`، `GET /shares`، `DELETE /shares/:id` | SHARE |
| Audit | `GET /audit` (فیلتر بر اساس کاربر/عملیات/بازه) | مدیران (در محدوده) |
| Quarantine | `GET /admin/quarantine` (فقط متادیتا)، `DELETE /admin/quarantine/:versionId` | مدیران |
| Policy | `GET/PUT /admin/settings`، `GET/PUT /admin/blocked-extensions`، `GET/PUT /admin/retention-policies` | مدیر ارشد |
| Health | `GET /health/live`، `GET /health/ready` | شبکه‌ی داخلی |
