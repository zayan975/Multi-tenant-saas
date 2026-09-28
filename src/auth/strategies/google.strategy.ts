import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(config: ConfigService) {
    super({
      clientID: config.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      clientSecret: config.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: config.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  
  validate(_accessToken: string, _refreshToken: string, profile: any) {
    const email = profile.emails?.[0]; //Agar emails exist karta hai to first email lo, warna error mat throw karo.
    return {
      googleId: profile.id,
      email: email?.value,
      emailVerified: (email?.verified ?? profile._json?.email_verified) === true,
      firstName: profile.name?.givenName ?? '',
      lastName: profile.name?.familyName ?? '',
    };
  }
}