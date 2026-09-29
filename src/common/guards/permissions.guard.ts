import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator.js';
import { ROLE_PERMISSIONS } from '../../permissions/role-permissions.map.js';
import { Permission } from '../../permissions/permission.enum.js';
import { Role } from '@prisma/client';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.get<Permission[]>(
      PERMISSIONS_KEY,
      context.getHandler(),
    );
    if (!required?.length) return true;

    const req = context.switchToHttp().getRequest();
    if (req.user?.isSuperAdmin) return true;

    const role = req.membership?.role as Role | undefined;
    const granted = role ? ROLE_PERMISSIONS[role] : [];
    const hasAll = required.every((p) => granted.includes(p));
    if (!hasAll) throw new ForbiddenException('Insufficient permissions');

    return true;
  }
}
