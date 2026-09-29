import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service.js';

@Injectable()
export class OrgMembershipGuard implements CanActivate {
  constructor(private prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const organizationId = req.params.id;

    if (req.user.isSuperAdmin) {
      req.membership = { role: 'SUPER_ADMIN' as const };
      return true;
    }

    const membership = await this.prisma.membership.findUnique({
      where: {
        userId_organizationId: { userId: req.user.sub, organizationId },
      },
    });

    if (!membership) {
      throw new ForbiddenException('Not a member of this organization');
    }

    req.membership = membership;
    return true;
  }
}