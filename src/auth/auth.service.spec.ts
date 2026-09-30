import * as bcrypt from 'bcrypt';
import { createHash } from 'crypto';

describe('AuthService — password hashing (unit)', () => {
  it('hashes a password so the raw value never matches directly', async () => {
    const raw = 'password123';
    const hash = await bcrypt.hash(raw, 10);

    expect(hash).not.toEqual(raw);
    expect(await bcrypt.compare(raw, hash)).toBe(true);
    expect(await bcrypt.compare('wrongpassword', hash)).toBe(false);
  });

  it('produces a different hash each time due to bcrypt salting', async () => {
    const raw = 'password123';
    const hash1 = await bcrypt.hash(raw, 10);
    const hash2 = await bcrypt.hash(raw, 10);

    expect(hash1).not.toEqual(hash2);
  });
});

describe('AuthService — refresh token hashing (unit)', () => {
  function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  it('is deterministic — same token always produces the same hash', () => {
    const token = 'some.jwt.token.value';
    expect(hashToken(token)).toEqual(hashToken(token));
  });

  it('produces different hashes for different tokens', () => {
    expect(hashToken('token-a')).not.toEqual(hashToken('token-b'));
  });
});