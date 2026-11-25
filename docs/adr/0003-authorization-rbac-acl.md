# ADR-0003: مدل مجوز (RBAC + ACL)

**وضعیت:** پذیرفته‌شده

## تصمیم

- **فقط allow** در نسخه اول؛ deny صریح وجود ندارد. این کار ارزیابی را قابل اثبات و تست‌پذیر نگه می‌دارد.
- مجوزهای محتوا: `VIEW`، `DOWNLOAD`، `UPLOAD`، `EDIT_METADATA`، `DELETE`، `SHARE`، `MANAGE_VERSIONS` (VIEW از DOWNLOAD جداست).
- **RBAC** فقط برای اختیارات مدیریتی در scope واحد سازمانی است (`MANAGE_USERS`، `MANAGE_ORG`، `MANAGE_POLICY`، `VIEW_AUDIT`). دسترسی مدیر به **محتوای فایل** فقط با `ADMIN_CONTENT_ACCESS` صریح و همیشه با Audit.
- فایل‌ها ACL مستقل ندارند؛ دسترسی فایل از پوشه می‌آید و shareها موارد استثنا را اضافه می‌کنند.

## الگوریتم دسترسی مؤثر

برای کاربر U روی پوشه F: اجتماع مجوزهای `folder_acl` که principal آن‌ها U یا یکی از گروه‌های U است، روی F و روی اجداد F، با این قید: از F به سمت ریشه حرکت کن؛ ACL پوشه‌ای که `inherit_acl = false` دارد هنوز اعمال می‌شود ولی از آن بالاتر دیده نمی‌شود؛ ورودی ancestor فقط اگر `inherit = true` باشد به فرزند می‌رسد. سپس shareهای فعال (منقضی‌نشده و revoke‌نشده) اضافه می‌شوند.

اجداد با ستون `path_ids` پوشه پیدا می‌شوند (بدون recursive query).

## تست‌های اجباری

تست منفی برای هر endpoint و هر object: list، HEAD/PATCH آپلود، finalize، دانلود، share، version، restore؛ تغییر File ID و URL (IDOR)؛ انتقال پوشه و تغییر ارث‌بری؛ revoke فوری share؛ تغییر عضویت گروه.
