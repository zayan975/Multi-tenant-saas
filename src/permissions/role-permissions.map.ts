import { Role } from '@prisma/client';
import { Permission } from './permission.enum.js';

// SUPER_ADMIN is not looked up here — it bypasses this map entirely (see PermissionsGuard)
export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  SUPER_ADMIN: [],
  ORGANIZATION_ADMIN: [
    Permission.VIEW_ORGANIZATION,
    Permission.MANAGE_ORGANIZATION,
    Permission.VIEW_MEMBERS,
    Permission.MANAGE_MEMBERS,
  ],
  MANAGER: [Permission.VIEW_ORGANIZATION, Permission.VIEW_MEMBERS],
  MEMBER: [Permission.VIEW_ORGANIZATION],
};