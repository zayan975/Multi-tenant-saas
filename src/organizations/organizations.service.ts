import {
  Injectable,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { Role } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service.js';
import { CreateOrganizationDto } from './dto/create-organization.dto.js';
import { UpdateOrganizationDto } from './dto/update-organization.dto.js';
import { AddMemberDto } from './dto/add-member.dto.js';
import { UpdateMemberDto } from './dto/update-member.dto.js';

@Injectable()
export class OrganizationsService {
  constructor(private prisma: PrismaService) {}

  async create(userId: string, dto: CreateOrganizationDto) {
    // creator automatically becomes ORGANIZATION_ADMIN of their new org
    return this.prisma.organization.create({
      data: {
        name: dto.name,
        memberships: {
          create: { userId, role: Role.ORGANIZATION_ADMIN },
        },
      },
    });
  }

  async findOne(id: string) {
    const org = await this.prisma.organization.findUnique({ where: { id } });
    if (!org) throw new NotFoundException('Organization not found');
    return org;
  }

  async update(id: string, dto: UpdateOrganizationDto) {
    // findOne first so a bad :id gives a clean 404, not a raw Prisma error
    await this.findOne(id);
    return this.prisma.organization.update({ where: { id }, data: { name: dto.name } });
  }

  async listMembers(organizationId: string) {
    return this.prisma.membership.findMany({
      where: { organizationId },
      include: { user: { select: { id: true, firstName: true, lastName: true, email: true } } },
    });
  }

  async addMember(organizationId: string, dto: AddMemberDto) {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (!user) throw new NotFoundException('No user with that email');

    const existing = await this.prisma.membership.findUnique({
      where: { userId_organizationId: { userId: user.id, organizationId } },
    });
    if (existing) throw new ConflictException('User is already a member');

    return this.prisma.membership.create({
      data: { userId: user.id, organizationId, role: dto.role },
    });
  }

  async updateMember(organizationId: string, memberId: string, dto: UpdateMemberDto) {
    const membership = await this.getScopedMembership(organizationId, memberId);

    if (membership.role === Role.ORGANIZATION_ADMIN && dto.role !== Role.ORGANIZATION_ADMIN) {
      await this.assertNotLastAdmin(organizationId);
    }

    return this.prisma.membership.update({ where: { id: memberId }, data: { role: dto.role } });
  }

  async removeMember(organizationId: string, memberId: string) {
    const membership = await this.getScopedMembership(organizationId, memberId);

    if (membership.role === Role.ORGANIZATION_ADMIN) {
      await this.assertNotLastAdmin(organizationId);
    }

    await this.prisma.membership.delete({ where: { id: memberId } });
    return { message: 'Member removed' };
  }

  /**
   * Fetches a membership by its id, but only if it belongs to the given
   * organization. This is the key IDOR guard: a memberId from a DIFFERENT
   * org must come back as 404, never leak that the row exists elsewhere.
   */
  private async getScopedMembership(organizationId: string, memberId: string) {
    const membership = await this.prisma.membership.findFirst({
      where: { id: memberId, organizationId },
    });
    if (!membership) throw new NotFoundException('Member not found');
    return membership;
  }

  private async assertNotLastAdmin(organizationId: string) {
    const adminCount = await this.prisma.membership.count({
      where: { organizationId, role: Role.ORGANIZATION_ADMIN },
    });
    if (adminCount <= 1) {
      throw new ForbiddenException('Organization must keep at least one admin');
    }
  }
}