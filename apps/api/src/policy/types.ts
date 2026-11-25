export type Role = 'super_admin' | 'region_manager' | 'user';

export type ContentPermission =
  | 'VIEW'
  | 'DOWNLOAD'
  | 'UPLOAD'
  | 'EDIT_METADATA'
  | 'DELETE'
  | 'SHARE'
  | 'MANAGE_VERSIONS'
  | 'MANAGE_ACL';

export interface Actor {
  id: string;
  role: Role;
  managedBy: string | null;
  status: 'active' | 'disabled';
}

export interface UserRef {
  id: string;
  role: Role;
  managedBy: string | null;
  status: 'active' | 'disabled';
}
