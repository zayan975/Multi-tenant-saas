import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { TokenType } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';

type GoogleUser = {
  googleId: string;
  email?: string;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
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

    const token = await this.createToken(
      user.id,
      TokenType.EMAIL_VERIFICATION,
      24 * 60,
    );
    this.sendMail(
      user.email,
      'Verify your email',
      `Verification token: ${token}`,
    );

    const { password, ...safeUser } = user;
    return safeUser;
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    // Google-only accounts have no password, so they cannot log in this way
    if (!user || !user.password)
      throw new UnauthorizedException('Invalid credentials');

    const passwordMatches = await bcrypt.compare(dto.password, user.password);
    if (!passwordMatches)
      throw new UnauthorizedException('Invalid credentials');

    return this.issueTokens(user.id, user.email);
  }

  async googleLogin(g: GoogleUser) {
    if (!g.email || !g.emailVerified) {
      throw new UnauthorizedException('Google email not verified');
    }

    let user = await this.prisma.user.findUnique({
      where: { googleId: g.googleId },
    });

    if (!user) {
      const existing = await this.prisma.user.findUnique({
        where: { email: g.email },
      });

      if (existing) {
        // Link Google to the existing account. If that email was never verified,
        // whoever registered it may not own it, so their password is removed
        // and their sessions are killed. Google has now proven who owns the email.
        const unverified = !existing.emailVerified;

        user = await this.prisma.user.update({
          where: { id: existing.id },
          data: {
            googleId: g.googleId,
            emailVerified: true,
            ...(unverified ? { password: null } : {}),
          },
        });

        if (unverified) {
          await this.prisma.refreshToken.updateMany({
            where: { userId: existing.id },
            data: { revoked: true },
          });
        }
      } else {
        user = await this.prisma.user.create({
          data: {
            email: g.email,
            googleId: g.googleId,
            firstName: g.firstName,
            lastName: g.lastName,
            emailVerified: true,
          },
        });
      }
    }

    return this.issueTokens(user.id, user.email);
  }

  /**
   * Refresh tokens are long random JWT strings (high entropy already),
   * so we don't need bcrypt's slow salted hashing here — SHA-256 gives
   * a full-length, deterministic hash we can look up directly in the DB.
   */
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private async issueTokens(userId: string, email: string) {
    const accessToken = this.jwt.sign(
      { sub: userId, email },
      {
        secret: this.config.getOrThrow('JWT_SECRET'),
        expiresIn: this.config.getOrThrow('JWT_EXPIRES_IN'),
      },
    );

    const refreshToken = this.jwt.sign(
      { sub: userId, jti: randomUUID() },
      {
        secret: this.config.getOrThrow('JWT_REFRESH_SECRET'),
        expiresIn: this.config.getOrThrow('JWT_REFRESH_EXPIRES_IN'),
      },
    );

    const tokenHash = this.hashToken(refreshToken);

    const expiresInDays = Number(
      this.config.getOrThrow('REFRESH_TOKEN_EXPIRES_DAYS'),
    );
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);

    await this.prisma.refreshToken.create({
      data: { tokenHash, userId, expiresAt },
    });

    return { accessToken, refreshToken };
  }

  async refresh(oldRefreshToken: string) {
    let payload: any;
    try {
      payload = this.jwt.verify(oldRefreshToken, {
        secret: this.config.getOrThrow('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const tokenHash = this.hashToken(oldRefreshToken);

    const matchedToken = await this.prisma.refreshToken.findFirst({
      where: { tokenHash, userId: payload.sub, revoked: false },
    });

    if (!matchedToken) {
      // Reuse detection: token is a valid JWT but not found as an
      // active row in the DB — either already used or forged.
      // Revoke EVERY session of this user as a precaution.
      await this.prisma.refreshToken.updateMany({
        where: { userId: payload.sub },
        data: { revoked: true },
      });
      throw new UnauthorizedException(
        'Refresh token reuse detected — all sessions revoked',
      );
    }

    // Rotation: revoke the old token, issue a fresh pair
    await this.prisma.refreshToken.update({
      where: { id: matchedToken.id },
      data: { revoked: true },
    });

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user) throw new UnauthorizedException('User not found');

    return this.issueTokens(user.id, user.email);
  }

  async logout(refreshToken: string) {
    let payload: any;
    try {
      payload = this.jwt.verify(refreshToken, {
        secret: this.config.getOrThrow('JWT_REFRESH_SECRET'),
      });
    } catch {
      return { message: 'Logged out' }; // invalid token — fail silently, don't leak info
    }

    const tokenHash = this.hashToken(refreshToken);

    await this.prisma.refreshToken.updateMany({
      where: { tokenHash, userId: payload.sub, revoked: false },
      data: { revoked: true },
    });

    return { message: 'Logged out' };
  }

  async logoutAll(userId: string) {
    await this.prisma.refreshToken.updateMany({
      where: { userId },
      data: { revoked: true },
    });
    return { message: 'Logged out from all devices' };
  }

  async verifyEmail(token: string) {
    // consumeToken checks: token valid hai, sahi type ka hai,
    // expire nahi hua, aur pehle use nahi hua
    const record = await this.consumeToken(token, TokenType.EMAIL_VERIFICATION);
    await this.prisma.user.update({
      where: { id: record.userId },
      data: { emailVerified: true },
    });
    return { message: 'Email verified' };
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (user) {
      const token = await this.createToken(
        user.id,
        TokenType.PASSWORD_RESET,
        60,
      );
      this.sendMail(user.email, 'Reset your password', `Reset token: ${token}`);
    }
    // same reply either way, so nobody can find out which emails are registered
    return { message: 'If that email exists, a reset link has been sent' };
  }

  async resetPassword(token: string, newPassword: string) {
    const record = await this.consumeToken(token, TokenType.PASSWORD_RESET);
    const password = await bcrypt.hash(newPassword, 10);

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { password },
      }),
      // password changed, so every existing session must die
      this.prisma.refreshToken.updateMany({
        where: { userId: record.userId },
        data: { revoked: true },
      }),
    ]);
    return { message: 'Password reset successful' };
  }

  private async createToken(
    userId: string,
    type: TokenType,
    ttlMinutes: number,
  ) {
    // older unused tokens of the same type are removed, only the latest one works
    await this.prisma.userToken.deleteMany({ where: { userId, type } });

    const token = randomBytes(32).toString('hex');
    await this.prisma.userToken.create({
      data: {
        tokenHash: this.hashToken(token),
        type,
        userId,
        expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
      },
    });
    return token;
  }

  private async consumeToken(token: string, type: TokenType) {
    const record = await this.prisma.userToken.findFirst({
      where: {
        tokenHash: this.hashToken(token),
        type,
        expiresAt: { gt: new Date() },
      },
    });
    if (!record) throw new BadRequestException('Invalid or expired token');

    // delete makes it single-use; the count check stops two parallel requests both succeeding
    const { count } = await this.prisma.userToken.deleteMany({
      where: { id: record.id },
    });
    if (count === 0) throw new BadRequestException('Invalid or expired token');

    return record;
  }

  private sendMail(to: string, subject: string, body: string) {
    // dev mock: the "email" shows up in the server terminal
    this.logger.log(`MAIL to=${to} | ${subject} | ${body}`);
  }
}