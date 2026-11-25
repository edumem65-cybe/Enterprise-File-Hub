-- DRAFT 0003: scan_jobs، retention، legal hold، ورود محلی و session، مجوز MANAGE_ACL، تنظیمات آپلود (ADR-0006/0007/0008).
-- مقادیر retention و تنظیمات زیر مقدار اولیه‌اند و باید با سیاست سازمان تطبیق داده شوند.

-- مجوز Manage (مدیریت ACL پوشه)
ALTER TABLE folder_acl DROP CONSTRAINT folder_acl_permission_check;
ALTER TABLE folder_acl ADD CONSTRAINT folder_acl_permission_check
  CHECK (permission IN ('VIEW','DOWNLOAD','UPLOAD','EDIT_METADATA','DELETE','SHARE','MANAGE_VERSIONS','MANAGE_ACL'));

-- کارهای اسکن (برای داشبورد، retry و عیب‌یابی)
CREATE TABLE scan_jobs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_version_id   uuid NOT NULL REFERENCES file_versions(id),
  state             text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','clean','infected','error','timeout','skipped_limit')),
  attempt           integer NOT NULL DEFAULT 0,
  engine            text,
  signature_version text,
  result_detail     text,
  queued_at         timestamptz NOT NULL DEFAULT now(),
  started_at        timestamptz,
  finished_at       timestamptz
);
CREATE INDEX scan_jobs_state_idx ON scan_jobs (state, queued_at);
CREATE INDEX scan_jobs_version_idx ON scan_jobs (file_version_id);

-- سیاست نگهداری
CREATE TABLE retention_policies (
  id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                        text NOT NULL UNIQUE,
  trash_days                  integer NOT NULL CHECK (trash_days >= 0),
  old_version_days            integer NOT NULL CHECK (old_version_days >= 0),
  min_versions_kept           integer NOT NULL DEFAULT 1 CHECK (min_versions_kept >= 1),
  permanent_delete_admin_only boolean NOT NULL DEFAULT false,
  is_default                  boolean NOT NULL DEFAULT false,
  created_at                  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX retention_policies_one_default ON retention_policies (is_default) WHERE is_default;
INSERT INTO retention_policies (name, trash_days, old_version_days, permanent_delete_admin_only, is_default) VALUES
  ('standard', 30, 90, false, true),
  ('important', 90, 365, true, false);

ALTER TABLE files
  ADD COLUMN retention_policy_id uuid REFERENCES retention_policies(id), -- NULL = سیاست پیش‌فرض
  ADD COLUMN legal_hold boolean NOT NULL DEFAULT false,                 -- تا رفع hold هیچ حذف دائمی‌ای مجاز نیست
  ADD COLUMN purge_reason text;                                          -- دلیل حذف دائمی (الزامی برای فایل‌های مهم)

ALTER TABLE file_versions
  ADD COLUMN immutable_until timestamptz; -- تا این زمان حذف نسخه ممنوع است

-- ورود محلی (ADR-0008). NULL یعنی ورود محلی برای این کاربر فعال نیست.
ALTER TABLE users
  ADD COLUMN password_hash         text,
  ADD COLUMN password_changed_at   timestamptz,
  ADD COLUMN must_change_password  boolean NOT NULL DEFAULT true,
  ADD COLUMN failed_login_count    integer NOT NULL DEFAULT 0,
  ADD COLUMN locked_until          timestamptz;

CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   text NOT NULL UNIQUE, -- فقط hash توکن، نه خود توکن
  csrf_secret  text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  ip           inet,
  user_agent   text
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- تنظیمات آپلود (قابل تغییر توسط مدیر ارشد)
INSERT INTO app_settings (key, value) VALUES
  ('max_concurrent_uploads_per_user', '3'::jsonb),
  ('tus_chunk_bytes', '16777216'::jsonb),
  ('upload_session_ttl_hours', '24'::jsonb),
  ('quarantine_retention_days', '30'::jsonb);
