-- DRAFT 0001_init.sql (PostgreSQL 16). پیش‌نویس؛ قبل از اجرا بازبینی شود.
-- قواعد: شناسه UUID، timestamptz، text + CHECK به‌جای enum، محتوای فایل هرگز در DB نیست.
-- جدول sessions (ADR-0002) در migration بعدی اضافه می‌شود.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id   text UNIQUE,
  username      text NOT NULL UNIQUE,
  email         text,
  display_name  text NOT NULL,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE org_units (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_id  uuid REFERENCES org_units(id),
  name       text NOT NULL,
  path_ids   text NOT NULL, -- '/rootId/childId/' شامل خودش
  manager_id uuid REFERENCES users(id),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (parent_id, name)
);
CREATE INDEX org_units_path_idx ON org_units (path_ids text_pattern_ops);

CREATE TABLE groups (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_unit_id uuid REFERENCES org_units(id),
  name        text NOT NULL,
  source      text NOT NULL DEFAULT 'local' CHECK (source IN ('local','idp')),
  external_id text,
  UNIQUE (source, name)
);

CREATE TABLE group_members (
  group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user_idx ON group_members (user_id);

CREATE TABLE roles (
  id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL UNIQUE,
  name text NOT NULL
);

CREATE TABLE permissions (
  code        text PRIMARY KEY,
  description text
);
INSERT INTO permissions (code, description) VALUES
  ('VIEW','مشاهده در فهرست و metadata'),
  ('DOWNLOAD','دانلود محتوا'),
  ('UPLOAD','آپلود فایل/نسخه جدید'),
  ('EDIT_METADATA','تغییر نام/انتقال/metadata'),
  ('DELETE','حذف به Trash'),
  ('SHARE','اشتراک‌گذاری'),
  ('MANAGE_VERSIONS','مدیریت و بازیابی نسخه‌ها'),
  ('MANAGE_USERS','مدیریت کاربران'),
  ('MANAGE_ORG','مدیریت واحدها و گروه‌ها'),
  ('MANAGE_POLICY','سیاست‌ها، سهمیه و retention'),
  ('VIEW_AUDIT','مشاهده Audit در scope'),
  ('ADMIN_CONTENT_ACCESS','دسترسی صریح مدیر به محتوا (همیشه Audit)');

CREATE TABLE role_permissions (
  role_id         uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_code text NOT NULL REFERENCES permissions(code),
  PRIMARY KEY (role_id, permission_code)
);

CREATE TABLE user_roles (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id     uuid NOT NULL REFERENCES roles(id),
  org_unit_id uuid REFERENCES org_units(id), -- NULL = سراسری
  UNIQUE NULLS NOT DISTINCT (user_id, role_id, org_unit_id)
);

CREATE TABLE folders (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_id   uuid REFERENCES folders(id),
  org_unit_id uuid NOT NULL REFERENCES org_units(id),
  owner_id    uuid NOT NULL REFERENCES users(id),
  name        text NOT NULL,
  path_ids    text NOT NULL, -- '/rootId/.../id/' شامل خودش
  inherit_acl boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);
CREATE UNIQUE INDEX folders_unique_name ON folders
  (COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name))
  WHERE deleted_at IS NULL;
CREATE INDEX folders_parent_idx ON folders (parent_id);
CREATE INDEX folders_path_idx ON folders (path_ids text_pattern_ops);
CREATE INDEX folders_org_idx ON folders (org_unit_id);

-- ADR-0003: فقط allow؛ deny صریح در نسخه اول وجود ندارد.
CREATE TABLE folder_acl (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  folder_id      uuid NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  principal_type text NOT NULL CHECK (principal_type IN ('user','group')),
  principal_id   uuid NOT NULL,
  permission     text NOT NULL CHECK (permission IN ('VIEW','DOWNLOAD','UPLOAD','EDIT_METADATA','DELETE','SHARE','MANAGE_VERSIONS')),
  inherit        boolean NOT NULL DEFAULT true,
  created_by     uuid REFERENCES users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (folder_id, principal_type, principal_id, permission)
);
CREATE INDEX folder_acl_principal_idx ON folder_acl (principal_type, principal_id);

CREATE TABLE files (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  folder_id          uuid NOT NULL REFERENCES folders(id),
  owner_id           uuid NOT NULL REFERENCES users(id),
  display_name       text NOT NULL,
  current_version_id uuid, -- فقط به نسخه‌ی scan_state = clean اشاره می‌کند (در سرویس + تست enforce شود)
  status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','trashed','purged')),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz
);
CREATE UNIQUE INDEX files_unique_name ON files (folder_id, lower(display_name)) WHERE status IN ('pending','active');
CREATE INDEX files_folder_idx ON files (folder_id) WHERE status = 'active';
CREATE INDEX files_name_trgm_idx ON files USING gin (display_name gin_trgm_ops);

CREATE TABLE file_versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id       uuid NOT NULL REFERENCES files(id),
  version_no    integer NOT NULL,
  blob_key      text NOT NULL UNIQUE, -- ADR-0004؛ یک blob برای هر نسخه (بدون dedup)
  size_bytes    bigint NOT NULL CHECK (size_bytes >= 0),
  sha256        char(64) NOT NULL,
  detected_mime text,
  scan_state    text NOT NULL DEFAULT 'quarantined' CHECK (scan_state IN ('quarantined','scanning','clean','rejected','failed')),
  reject_reason text,
  created_by    uuid NOT NULL REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (file_id, version_no)
);
CREATE INDEX file_versions_file_idx ON file_versions (file_id);

ALTER TABLE files
  ADD CONSTRAINT files_current_version_fk FOREIGN KEY (current_version_id) REFERENCES file_versions(id);

CREATE TABLE upload_sessions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tus_upload_id  text NOT NULL UNIQUE,
  user_id        uuid NOT NULL REFERENCES users(id),
  folder_id      uuid NOT NULL REFERENCES folders(id),
  file_id        uuid REFERENCES files(id), -- پر باشد یعنی نسخه جدید برای فایل موجود
  original_name  text NOT NULL,
  expected_size  bigint NOT NULL CHECK (expected_size > 0),
  offset_bytes   bigint NOT NULL DEFAULT 0,
  state          text NOT NULL DEFAULT 'created' CHECK (state IN ('created','uploading','finalizing','finalized','failed','expired','cancelled')),
  finalize_key   uuid UNIQUE, -- idempotency کلید finalize
  expires_at     timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX upload_sessions_expiry_idx ON upload_sessions (expires_at) WHERE state IN ('created','uploading');

-- ADR-0005: سهمیه در سطح واحد سازمانی
CREATE TABLE quota_usage (
  org_unit_id    uuid PRIMARY KEY REFERENCES org_units(id),
  quota_bytes    bigint NOT NULL CHECK (quota_bytes >= 0),
  used_bytes     bigint NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
  reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
-- رزرو اتمیک (نمونه):
--   UPDATE quota_usage SET reserved_bytes = reserved_bytes + $n, updated_at = now()
--   WHERE org_unit_id = $1 AND used_bytes + reserved_bytes + $n <= quota_bytes;  -- 0 ردیف = quota exceeded

CREATE TABLE quota_reservations (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  upload_session_id uuid NOT NULL UNIQUE REFERENCES upload_sessions(id),
  org_unit_id       uuid NOT NULL REFERENCES org_units(id),
  bytes             bigint NOT NULL CHECK (bytes > 0),
  state             text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','committed','released')),
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE shares (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_type  text NOT NULL CHECK (resource_type IN ('file','folder')),
  resource_id    uuid NOT NULL,
  principal_type text NOT NULL CHECK (principal_type IN ('user','group')),
  principal_id   uuid NOT NULL,
  permissions    text[] NOT NULL,
  expires_at     timestamptz,
  revoked_at     timestamptz,
  created_by     uuid NOT NULL REFERENCES users(id),
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shares_principal_idx ON shares (principal_type, principal_id) WHERE revoked_at IS NULL;
CREATE INDEX shares_resource_idx ON shares (resource_type, resource_id);

-- Append-only: نقش برنامه نباید UPDATE/DELETE/TRUNCATE داشته باشد:
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM <app_role>;
CREATE TABLE audit_events (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  actor_id      uuid,
  action        text NOT NULL,
  resource_type text,
  resource_id   uuid,
  outcome       text NOT NULL CHECK (outcome IN ('success','denied','error')),
  ip            inet,
  user_agent    text,
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_actor_idx ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX audit_resource_idx ON audit_events (resource_type, resource_id, occurred_at DESC);

CREATE TABLE outbox (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  topic        text NOT NULL,
  payload      jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);
CREATE INDEX outbox_pending_idx ON outbox (id) WHERE processed_at IS NULL;
