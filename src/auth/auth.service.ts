import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) throw new ConflictException('Email already registered');

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        firstName: dto.firstName,
        lastName: dto.lastName,
        email: dto.email,
        password: hashedPassword,
      },
    });

    const { password, ...safeUser } = user;
    return safeUser;
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const passwordMatches = await bcrypt.compare(dto.password, user.password);
    if (!passwordMatches) throw new UnauthorizedException('Invalid credentials');

    return this.issueTokens(user.id, user.email);
  }

  private async issueTokens(userId: string, email: string) {
    const accessToken = this.jwt.sign(
      { sub: userId, email },
      { secret: this.config.get('JWT_SECRET'), expiresIn: this.config.get('JWT_EXPIRES_IN') },
    );

    const refreshToken = this.jwt.sign(
      { sub: userId },
      { secret: this.config.get('JWT_REFRESH_SECRET'), expiresIn: this.config.get('JWT_REFRESH_EXPIRES_IN') },
    );

    const tokenHash = await bcrypt.hash(refreshToken, 10);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.config.get('JWT_REFRESH_EXPIRES_IN'));

    await this.prisma.refreshToken.create({
      data: { tokenHash, userId, expiresAt },
    });

    return { accessToken, refreshToken };
  }

  async refresh(oldRefreshToken: string) {
    let payload: any;
    try {
      payload = this.jwt.verify(oldRefreshToken, { secret: this.config.get('JWT_REFRESH_SECRET') });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const storedTokens = await this.prisma.refreshToken.findMany({
      where: { userId: payload.sub, revoked: false },
    });

    let matchedToken = null;
    for (const t of storedTokens) {
      if (await bcrypt.compare(oldRefreshToken, t.tokenHash)) {
        matchedToken = t;
        break;
      }
    }

    if (!matchedToken) {
      // Reuse detection: token valid JWT hai but DB mein nahi mila ya already revoked
      // matlab ya to already use ho chuka hai ya kabhi issue hi nahi hua — sab tokens revoke kardo
      await this.prisma.refreshToken.updateMany({
        where: { userId: payload.sub },
        data: { revoked: true },
      });
      throw new UnauthorizedException('Refresh token reuse detected — all sessions revoked');
    }

    // Rotation: purana revoke, naya issue
    await this.prisma.refreshToken.update({
      where: { id: matchedToken.id },
      data: { revoked: true },
    });

    const user = await this.prisma.user.findUnique({ where: { id: payload.sub } });
    return this.issueTokens(user.id, user.email);
  }

  async logout(refreshToken: string) {
    let payload: any;
    try {
      payload = this.jwt.verify(refreshToken, { secret: this.config.get('JWT_REFRESH_SECRET') });
    } catch {
      return { message: 'Logged out' }; // invalid token bhi silently ignore karo, info leak na ho
    }

    const storedTokens = await this.prisma.refreshToken.findMany({
      where: { userId: payload.sub, revoked: false },
    });

    for (const t of storedTokens) {
      if (await bcrypt.compare(refreshToken, t.tokenHash)) {
        await this.prisma.refreshToken.update({ where: { id: t.id }, data: { revoked: true } });
        break;
      }
    }

    return { message: 'Logged out' };
  }

  async logoutAll(userId: string) {
    await this.prisma.refreshToken.updateMany({
      where: { userId },
      data: { revoked: true },
    });
    return { message: 'Logged out from all devices' };
  }
  
}