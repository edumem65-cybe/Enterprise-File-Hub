import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canCreateUser, canManageUser, canShareWith, decideContentAccess, isInUserScope, userScope } from './access-policy.ts';
import type { Actor, UserRef } from './types.ts';

const admin: Actor = { id: 'admin', role: 'super_admin', managedBy: null, status: 'active' };
const regionA: Actor = { id: 'rA', role: 'region_manager', managedBy: 'admin', status: 'active' };
const regionB: Actor = { id: 'rB', role: 'region_manager', managedBy: 'admin', status: 'active' };
const userA1: Actor = { id: 'uA1', role: 'user', managedBy: 'rA', status: 'active' };
const userA2: Actor = { id: 'uA2', role: 'user', managedBy: 'rA', status: 'active' };
const userB1: Actor = { id: 'uB1', role: 'user', managedBy: 'rB', status: 'active' };
const none = new Set<never>();

test('user scope per role', () => {
  assert.deepEqual(userScope(admin), { kind: 'all' });
  assert.deepEqual(userScope(regionA), { kind: 'managed_by', managerId: 'rA' });
  assert.deepEqual(userScope(userA1), { kind: 'self', userId: 'uA1' });
  assert.deepEqual(userScope({ ...userA1, status: 'disabled' }), { kind: 'none' });
});

test('region manager sees own users but not another region', () => {
  assert.equal(isInUserScope(regionA, userA1), true);
  assert.equal(isInUserScope(regionA, regionA), true);
  assert.equal(isInUserScope(regionA, userB1), false);
  assert.equal(isInUserScope(regionA, admin), false);
  assert.equal(isInUserScope(userA1, userA2), false);
});

test('only super admin creates region managers; managers create only users under themselves', () => {
  assert.deepEqual(canCreateUser(admin, 'region_manager', admin), { ok: true, managedBy: 'admin' });
  assert.equal(canCreateUser(regionA, 'region_manager', regionA).ok, false);
  assert.deepEqual(canCreateUser(regionA, 'user', null), { ok: true, managedBy: 'rA' });
  assert.equal(canCreateUser(regionA, 'user', regionB).ok, false);
  assert.equal(canCreateUser(userA1, 'user', userA1).ok, false);
  assert.equal(canCreateUser(admin, 'user', userA1).ok, false); // a user cannot be a manager
  assert.deepEqual(canCreateUser(admin, 'user', regionB), { ok: true, managedBy: 'rB' });
  assert.deepEqual(canCreateUser(admin, 'super_admin', null), { ok: true, managedBy: null });
  assert.equal(canCreateUser({ ...admin, status: 'disabled' }, 'user', regionA).ok, false);
});

test('manage user: scope and self-lockout protection', () => {
  const target: UserRef = userA1;
  assert.equal(canManageUser(regionA, target, 'set_quota'), true);
  assert.equal(canManageUser(regionB, target, 'set_quota'), false);
  assert.equal(canManageUser(regionA, target, 'transfer'), false);
  assert.equal(canManageUser(regionA, regionA, 'disable'), false);
  assert.equal(canManageUser(admin, admin, 'disable'), false);
  assert.equal(canManageUser(admin, target, 'transfer'), true);
  assert.equal(canManageUser(userA1, userA1, 'view'), true);
  assert.equal(canManageUser(userA1, userA1, 'edit'), false);
  assert.equal(canManageUser(userA1, userA2, 'view'), false);
});

test('content access: owner always, region manager only inside own region, audited', () => {
  const owner = { id: 'uA1', managedBy: 'rA' };
  const own = decideContentAccess({ actor: userA1, owner, permission: 'DELETE' });
  assert.deepEqual(own, { allowed: true, via: 'owner', audit: false });
  const mgr = decideContentAccess({ actor: regionA, owner, permission: 'DOWNLOAD' });
  assert.deepEqual(mgr, { allowed: true, via: 'admin_scope', audit: true });
  const other = decideContentAccess({ actor: regionB, owner, permission: 'DOWNLOAD' });
  assert.deepEqual(other, { allowed: false, reason: 'no_grant' });
  const sup = decideContentAccess({ actor: admin, owner, permission: 'VIEW' });
  assert.equal(sup.allowed && sup.via, 'admin_scope');
});

test('content access: managers cannot upload or share on behalf of users', () => {
  const owner = { id: 'uA1', managedBy: 'rA' };
  assert.equal(decideContentAccess({ actor: regionA, owner, permission: 'UPLOAD' }).allowed, false);
  assert.equal(decideContentAccess({ actor: admin, owner, permission: 'SHARE' }).allowed, false);
});

test('content access: ACL and share grants, default deny, disabled actor', () => {
  const owner = { id: 'uA1', managedBy: 'rA' };
  const viaAcl = decideContentAccess({ actor: userB1, owner, permission: 'VIEW', aclPermissions: new Set(['VIEW']) });
  assert.equal(viaAcl.allowed && viaAcl.via, 'acl');
  const viaShare = decideContentAccess({ actor: userB1, owner, permission: 'DOWNLOAD', sharePermissions: new Set(['DOWNLOAD']) });
  assert.equal(viaShare.allowed && viaShare.via, 'share');
  assert.equal(decideContentAccess({ actor: userB1, owner, permission: 'DOWNLOAD', aclPermissions: new Set(['VIEW']), sharePermissions: none }).allowed, false);
  assert.deepEqual(decideContentAccess({ actor: { ...userA1, status: 'disabled' }, owner, permission: 'VIEW' }), { allowed: false, reason: 'actor_disabled' });
});

test('share targets stay inside the region', () => {
  assert.equal(canShareWith(userA1, userA2), true); // peer
  assert.equal(canShareWith(userA1, regionA), true); // own manager
  assert.equal(canShareWith(userA1, userB1), false); // other region
  assert.equal(canShareWith(userA1, regionB), false);
  assert.equal(canShareWith(regionA, userA1), true);
  assert.equal(canShareWith(regionA, userB1), false);
  assert.equal(canShareWith(admin, userB1), true);
  assert.equal(canShareWith(userA1, userA1), false);
  assert.equal(canShareWith(userA1, { ...userA2, status: 'disabled' }), false);
});
