-- DRAFT 0002: ساختار کاربری سه‌سطحی، سهمیه‌ی هر کاربر و سیاست فایل (ADR-0006).
-- فرض: روی دیتابیس خالی اجرا می‌شود (0001 هنوز جایی اعمال نشده). اگر PR می‌شود، می‌توان 0001 و 0002 را ادغام کرد.
-- اولین مدیر ارشد با دستور CLI بوت‌استرپ ساخته می‌شود، نه با SQL.

-- نقش‌ها ثابت‌اند و ماتریس مجوز در کد است؛ جدول‌های RBAC عمومی لازم نیستند.
DROP TABLE user_roles;
DROP TABLE role_permissions;
DROP TABLE roles;
DROP TABLE permissions;

ALTER TABLE users DROP COLUMN display_name;

ALTER TABLE users
  ADD COLUMN first_name         text NOT NULL,
  ADD COLUMN last_name          text NOT NULL,
  ADD COLUMN org_unit_id        uuid NOT NULL REFERENCES org_units(id),
  ADD COLUMN role               text NOT NULL CHECK (role IN ('super_admin','region_manager','user')),
  ADD COLUMN managed_by         uuid REFERENCES users(id),
  ADD COLUMN created_by         uuid REFERENCES users(id),
  ADD COLUMN phone              text,
  ADD COLUMN employee_code      text,
  ADD COLUMN job_title          text,
  ADD COLUMN notes              text,
  ADD COLUMN account_expires_at timestamptz,
  ADD COLUMN quota_bytes        bigint CHECK (quota_bytes >= 0),
  ADD COLUMN max_files          integer CHECK (max_files >= 0);

ALTER TABLE users ADD COLUMN display_name text GENERATED ALWAYS AS (first_name || ' ' || last_name) STORED;
ALTER TABLE users ALTER COLUMN email SET NOT NULL;

ALTER TABLE users
  ADD CONSTRAINT users_not_self_managed CHECK (managed_by IS DISTINCT FROM id),
  -- مدیر ارشد همیشه بدون مدیر بالادستی است و برعکس
  ADD CONSTRAINT users_hierarchy_chk CHECK ((role = 'super_admin') = (managed_by IS NULL)),
  -- سهمیه و حداکثر تعداد فایل برای همه به جز مدیر ارشد الزامی است
  ADD CONSTRAINT users_limits_chk CHECK (role = 'super_admin' OR (quota_bytes IS NOT NULL AND max_files IS NOT NULL));

CREATE UNIQUE INDEX users_email_uq ON users (lower(email));
CREATE UNIQUE INDEX users_employee_code_uq ON users (employee_code) WHERE employee_code IS NOT NULL;
CREATE INDEX users_managed_by_idx ON users (managed_by);
CREATE INDEX users_org_idx ON users (org_unit_id);
CREATE INDEX users_role_idx ON users (role);
CREATE INDEX users_name_trgm_idx ON users USING gin (display_name gin_trgm_ops);

-- مدیر منطقه فقط زیر مدیر ارشد؛ کاربر عادی زیر مدیر منطقه یا مدیر ارشد.
CREATE FUNCTION users_validate_hierarchy() RETURNS trigger AS $$
DECLARE parent_role text;
BEGIN
  IF NEW.managed_by IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT role INTO parent_role FROM users WHERE id = NEW.managed_by;
  IF NEW.role = 'region_manager' AND parent_role IS DISTINCT FROM 'super_admin' THEN
    RAISE EXCEPTION 'region_manager must be managed by super_admin';
  END IF;
  IF NEW.role = 'user' AND parent_role NOT IN ('region_manager','super_admin') THEN
    RAISE EXCEPTION 'user must be managed by region_manager or super_admin';
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_validate_hierarchy_trg
  BEFORE INSERT OR UPDATE OF role, managed_by ON users
  FOR EACH ROW EXECUTE FUNCTION users_validate_hierarchy();

-- سهمیه در سطح هر کاربر (جایگزین quota_usage سطح واحد در 0001)
DROP TABLE quota_reservations;
DROP TABLE quota_usage;

CREATE TABLE user_usage (
  user_id        uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  used_bytes     bigint  NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
  reserved_bytes bigint  NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
  file_count     integer NOT NULL DEFAULT 0 CHECK (file_count >= 0),
  reserved_files integer NOT NULL DEFAULT 0 CHECK (reserved_files >= 0),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION users_create_usage_row() RETURNS trigger AS $$
BEGIN
  INSERT INTO user_usage (user_id) VALUES (NEW.id);
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_create_usage_trg AFTER INSERT ON users
  FOR EACH ROW EXECUTE FUNCTION users_create_usage_row();

-- رزرو اتمیک هم‌زمان بایت و تعداد فایل (NULL = بدون محدودیت، فقط مدیر ارشد). صفر ردیف یعنی رد شده:
--   UPDATE user_usage uu
--      SET reserved_bytes = uu.reserved_bytes + $2, reserved_files = uu.reserved_files + $3, updated_at = now()
--     FROM users u
--    WHERE uu.user_id = u.id AND u.id = $1
--      AND (u.quota_bytes IS NULL OR uu.used_bytes + uu.reserved_bytes + $2 <= u.quota_bytes)
--      AND (u.max_files   IS NULL OR uu.file_count + uu.reserved_files + $3 <= u.max_files);
-- برای پیام دقیق (حجم یا تعداد) قبلاً مقادیر را در همان تراکنش بخوانید.
CREATE TABLE quota_reservations (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  upload_session_id uuid NOT NULL UNIQUE REFERENCES upload_sessions(id),
  user_id           uuid NOT NULL REFERENCES users(id),
  bytes             bigint NOT NULL CHECK (bytes > 0),
  files             smallint NOT NULL DEFAULT 1 CHECK (files IN (0,1)), -- 0 = نسخه‌ی جدید فایل موجود
  state             text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','committed','released')),
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX quota_reservations_user_idx ON quota_reservations (user_id, state);

-- قالب سهمیه برای تعریف سریع کاربر (مقدار هنگام ساخت به کاربر کپی می‌شود؛ تغییر قالب بر کاربران موجود اثر ندارد)
CREATE TABLE quota_profiles (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL UNIQUE,
  quota_bytes bigint  NOT NULL CHECK (quota_bytes >= 0),
  max_files   integer NOT NULL CHECK (max_files >= 0),
  created_by  uuid REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- سیاست فایل: همه‌ی نوع‌ها مجاز مگر مشکل‌ساز (آلوده، قابل اسکن‌نبودن، پسوند ممنوع، بیش از سقف اندازه) — ADR-0006
CREATE TABLE app_settings (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_by uuid REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO app_settings (key, value) VALUES ('max_file_bytes', '5368709120'::jsonb);

CREATE TABLE blocked_extensions (
  extension  text PRIMARY KEY CHECK (extension = lower(extension) AND extension NOT LIKE '.%'),
  reason     text,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO blocked_extensions (extension, reason) VALUES
  ('exe','اجرایی'), ('msi','اجرایی'), ('bat','اسکریپت'), ('cmd','اسکریپت'),
  ('com','اجرایی'), ('scr','اجرایی'), ('pif','اجرایی'), ('vbs','اسکریپت'),
  ('vbe','اسکریپت'), ('wsf','اسکریپت'), ('ps1','اسکریپت'), ('dll','کتابخانه‌ی اجرایی'),
  ('sys','درایور'), ('lnk','میانبر'), ('hta','اجرایی');

-- ایندکس برای دسترسی مدیران به فایل‌های زیرمجموعه (بر اساس مالک)
CREATE INDEX files_owner_idx ON files (owner_id) WHERE status IN ('pending','active','trashed');
CREATE INDEX folders_owner_idx ON folders (owner_id);
