import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OrganizationsService } from './organizations.service.js';
import { OrgMembershipGuard } from '../common/guards/org-membership.guard.js';
import { PermissionsGuard } from '../common/guards/permissions.guard.js';
import { RequirePermissions } from '../common/decorators/permissions.decorator.js';
import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { Permission } from '../permissions/permission.enum.js';
import { CreateOrganizationDto } from './dto/create-organization.dto.js';
import { UpdateOrganizationDto } from './dto/update-organization.dto.js';
import { AddMemberDto } from './dto/add-member.dto.js';
import { UpdateMemberDto } from './dto/update-member.dto.js';

@Controller('organizations')
export class OrganizationsController {
  constructor(private orgService: OrganizationsService) {}

  // No OrgMembershipGuard here on purpose — this org doesn't exist yet,
  // so there's nothing to check membership against. Any authenticated user can create one.
  @Post()
  @UseGuards(AuthGuard('jwt'))
  create(@CurrentUser() user: any, @Body() dto: CreateOrganizationDto) {
    return this.orgService.create(user.sub, dto);
  }

  @Get(':id')
  @UseGuards(AuthGuard('jwt'), OrgMembershipGuard, PermissionsGuard)
  @RequirePermissions(Permission.VIEW_ORGANIZATION)
  findOne(@Param('id') id: string) {
    return this.orgService.findOne(id);
  }

  @Patch(':id')
  @UseGuards(AuthGuard('jwt'), OrgMembershipGuard, PermissionsGuard)
  @RequirePermissions(Permission.MANAGE_ORGANIZATION)
  update(@Param('id') id: string, @Body() dto: UpdateOrganizationDto) {
    return this.orgService.update(id, dto);
  }

  @Get(':id/members')
  @UseGuards(AuthGuard('jwt'), OrgMembershipGuard, PermissionsGuard)
  @RequirePermissions(Permission.VIEW_MEMBERS)
  listMembers(@Param('id') id: string) {
    return this.orgService.listMembers(id);
  }

  @Post(':id/members')
  @UseGuards(AuthGuard('jwt'), OrgMembershipGuard, PermissionsGuard)
  @RequirePermissions(Permission.MANAGE_MEMBERS)
  addMember(@Param('id') id: string, @Body() dto: AddMemberDto) {
    return this.orgService.addMember(id, dto);
  }

  @Patch(':id/members/:memberId')
  @UseGuards(AuthGuard('jwt'), OrgMembershipGuard, PermissionsGuard)
  @RequirePermissions(Permission.MANAGE_MEMBERS)
  updateMember(
    @Param('id') id: string,
    @Param('memberId') memberId: string,
    @Body() dto: UpdateMemberDto,
  ) {
    return this.orgService.updateMember(id, memberId, dto);
  }

  @Delete(':id/members/:memberId')
  @UseGuards(AuthGuard('jwt'), OrgMembershipGuard, PermissionsGuard)
  @RequirePermissions(Permission.MANAGE_MEMBERS)
  removeMember(@Param('id') id: string, @Param('memberId') memberId: string) {
    return this.orgService.removeMember(id, memberId);
  }
}