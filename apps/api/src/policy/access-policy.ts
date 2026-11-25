import type { Actor, ContentPermission, Role, UserRef } from './types.ts';

// ADR-0006: what a manager may do with files of users in their scope. Always audited.
export const ADMIN_SCOPE_PERMISSIONS: ReadonlySet<ContentPermission> = new Set(['VIEW', 'DOWNLOAD', 'DELETE']);

export type UserScope =
  | { kind: 'none' }
  | { kind: 'self'; userId: string }
  | { kind: 'managed_by'; managerId: string }
  | { kind: 'all' };

// Which users an actor may list/see. Must be applied in the service layer, not only in the UI.
export function userScope(actor: Actor): UserScope {
  if (actor.status !== 'active') return { kind: 'none' };
  if (actor.role === 'super_admin') return { kind: 'all' };
  if (actor.role === 'region_manager') return { kind: 'managed_by', managerId: actor.id };
  return { kind: 'self', userId: actor.id };
}

export function isInUserScope(actor: Actor, target: UserRef): boolean {
  const scope = userScope(actor);
  switch (scope.kind) {
    case 'all':
      return true;
    case 'managed_by':
      return target.id === actor.id || target.managedBy === scope.managerId;
    case 'self':
      return target.id === scope.userId;
    default:
      return false;
  }
}

export type CreateUserDecision = { ok: true; managedBy: string | null } | { ok: false; reason: string };

// parent = the user who will manage the new account (null only for a new super_admin).
export function canCreateUser(actor: Actor, newRole: Role, parent: UserRef | null): CreateUserDecision {
  if (actor.status !== 'active') return { ok: false, reason: 'actor_disabled' };
  if (actor.role === 'user') return { ok: false, reason: 'forbidden' };
  if (actor.role === 'region_manager') {
    if (newRole !== 'user') return { ok: false, reason: 'region_manager_can_only_create_users' };
    if (parent !== null && parent.id !== actor.id) return { ok: false, reason: 'outside_scope' };
    return { ok: true, managedBy: actor.id };
  }
  // super_admin
  if (newRole === 'super_admin') {
    return parent === null ? { ok: true, managedBy: null } : { ok: false, reason: 'super_admin_has_no_manager' };
  }
  if (parent === null || parent.status !== 'active') return { ok: false, reason: 'manager_required' };
  if (newRole === 'region_manager') {
    return parent.role === 'super_admin' ? { ok: true, managedBy: parent.id } : { ok: false, reason: 'region_manager_must_report_to_super_admin' };
  }
  return parent.role === 'region_manager' || parent.role === 'super_admin'
    ? { ok: true, managedBy: parent.id }
    : { ok: false, reason: 'user_must_report_to_manager' };
}

export type UserAction = 'view' | 'edit' | 'disable' | 'set_quota' | 'transfer';

export function canManageUser(actor: Actor, target: UserRef, action: UserAction): boolean {
  if (actor.status !== 'active') return false;
  if (actor.role === 'super_admin') return !(action === 'disable' && actor.id === target.id);
  if (actor.role === 'region_manager') {
    if (action === 'transfer') return false;
    if (target.id === actor.id) return action === 'view';
    return target.role === 'user' && target.managedBy === actor.id;
  }
  return action === 'view' && target.id === actor.id;
}

export interface ContentAccessInput {
  actor: Actor;
  owner: { id: string; managedBy: string | null };
  permission: ContentPermission;
  // Effective permissions of the actor on the folder (user + groups, after ACL inheritance).
  aclPermissions?: ReadonlySet<ContentPermission>;
  // Permissions from active (not expired, not revoked) shares.
  sharePermissions?: ReadonlySet<ContentPermission>;
}

export type AccessDecision =
  | { allowed: true; via: 'owner' | 'admin_scope' | 'acl' | 'share'; audit: boolean }
  | { allowed: false; reason: 'actor_disabled' | 'no_grant' };

// Order (ADR-0006): owner -> manager scope -> folder ACL -> share. Default deny.
export function decideContentAccess(input: ContentAccessInput): AccessDecision {
  const { actor, owner, permission } = input;
  if (actor.status !== 'active') return { allowed: false, reason: 'actor_disabled' };
  if (actor.id === owner.id) return { allowed: true, via: 'owner', audit: false };

  if (ADMIN_SCOPE_PERMISSIONS.has(permission)) {
    const inScope = actor.role === 'super_admin' || (actor.role === 'region_manager' && owner.managedBy === actor.id);
    if (inScope) return { allowed: true, via: 'admin_scope', audit: true };
  }
  if (input.aclPermissions?.has(permission)) return { allowed: true, via: 'acl', audit: false };
  if (input.sharePermissions?.has(permission)) return { allowed: true, via: 'share', audit: false };
  return { allowed: false, reason: 'no_grant' };
}

// Share targets: same region (manager and peers), or everyone below the actor for managers.
export function canShareWith(actor: Actor, target: UserRef): boolean {
  if (actor.status !== 'active' || target.status !== 'active' || actor.id === target.id) return false;
  if (actor.role === 'super_admin') return true;
  if (actor.role === 'region_manager') return target.managedBy === actor.id;
  return target.id === actor.managedBy || (actor.managedBy !== null && target.managedBy === actor.managedBy);
}
