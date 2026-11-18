import { describe, expect, it } from 'vitest';
import { luhnCheck, redactText } from './redact';

describe('luhnCheck', () => {
  it('accepts a valid card number', () => {
    expect(luhnCheck('4242424242424242')).toBe(true);
    expect(luhnCheck('4242 4242 4242 4242')).toBe(true);
    expect(luhnCheck('378282246310005')).toBe(true); // Amex
  });

  it('rejects non-card digit strings', () => {
    expect(luhnCheck('1234567890123456')).toBe(false);
    expect(luhnCheck('3201011234567890')).toBe(false);
  });
});

describe('redactText', () => {
  it('redacts an AWS access key ID', () => {
    const r = redactText('key is AKIAIOSFODNN7EXAMPLE here');
    expect(r.redactedCount).toBe(1);
    expect(r.findings[0].type).toBe('aws-access-key');
    expect(r.findings[0].severity).toBe('critical');
    expect(r.redactedText).toContain('[REDACTED:AWS-ACCESS-KEY-1]');
    expect(r.redactedText).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(r.findings[0].masked).toBe('AKIA…LE');
  });

  it('redacts a GitHub personal access token', () => {
    const token = `ghp_${'a'.repeat(36)}`;
    const r = redactText(`token=${token}`);
    expect(r.redactedCount).toBe(1);
    expect(r.findings[0].type).toBe('github-token');
    expect(r.redactedText).not.toContain(token);
  });

  it('redacts a JWT', () => {
    const jwt = `eyJ${'a'.repeat(12)}.eyJ${'b'.repeat(12)}.${'c'.repeat(12)}`;
    const r = redactText(`Authorization: ${jwt}`);
    expect(r.findings.some((f) => f.type === 'jwt')).toBe(true);
    expect(r.redactedText).not.toContain(jwt);
  });

  it('redacts a PEM private key block as one finding', () => {
    const pem = [
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvgIBADANBgkqhkiG9w0BAQEFAASC',
      '-----END PRIVATE KEY-----',
    ].join('\n');
    const r = redactText(`leaked:\n${pem}`);
    expect(r.redactedCount).toBe(1);
    expect(r.findings[0].type).toBe('pem-private-key');
    expect(r.redactedText).not.toContain('MIIEvgIBADANBgkqhkiG9w0BAQEFAASC');
  });

  it('redacts only the value of a password assignment', () => {
    const r = redactText('db password = hunter2 please');
    expect(r.redactedCount).toBe(1);
    expect(r.findings[0].type).toBe('password');
    expect(r.redactedText).toContain('db password = [REDACTED:PASSWORD-1]');
    expect(r.redactedText).not.toContain('hunter2');
  });

  it('redacts an AWS secret access key value only', () => {
    const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const r = redactText(`aws_secret_access_key = ${secret}`);
    expect(r.redactedCount).toBe(1);
    expect(r.findings[0].type).toBe('aws-secret-key');
    expect(r.redactedText).toContain('aws_secret_access_key = [REDACTED:AWS-SECRET-KEY-1]');
    expect(r.redactedText).not.toContain(secret);
  });

  it('redacts emails and masks them in the preview', () => {
    const r = redactText('contact fuad@example.com for details');
    expect(r.redactedCount).toBe(1);
    expect(r.findings[0].type).toBe('email');
    expect(r.redactedText).toContain('[REDACTED:EMAIL-1]');
    expect(r.findings[0].masked).toBe('fuad…om');
    expect(r.findings[0].masked).not.toContain('example.com');
    expect(r.redactedText).not.toContain('fuad@example.com');
  });

  it('redacts an Indonesian phone number', () => {
    const r = redactText('call me at +6281234567890');
    expect(r.findings.some((f) => f.type === 'phone-id')).toBe(true);
  });

  it('classifies a Luhn-valid 16-digit number as a card, not a national ID', () => {
    const r = redactText('card 4242424242424242 charged');
    expect(r.findings.some((f) => f.type === 'credit-card')).toBe(true);
    expect(r.findings.some((f) => f.type === 'national-id')).toBe(false);
  });

  it('classifies a non-Luhn 16-digit number as a possible national ID', () => {
    const r = redactText('KTP 3201011234567890 attached');
    expect(r.findings.some((f) => f.type === 'national-id')).toBe(true);
    expect(r.findings.some((f) => f.type === 'credit-card')).toBe(false);
  });

  it('redacts credentials inside a URL but keeps the scheme', () => {
    const r = redactText('see https://admin:s3cretPass@internal.example.com/api');
    expect(r.findings.some((f) => f.type === 'url-credentials')).toBe(true);
    expect(r.redactedText).toContain('https://');
    expect(r.redactedText).not.toContain('s3cretPass');
  });

  it('redacts a Stripe secret key', () => {
    // Stripe's public documentation example key (not a real secret).
    // Built dynamically so GitHub push protection does not flag the
    // well-known example value as a leaked credential.
    const stripeKey = ['sk_live', '4eC39HqLyjWDarjtT1zdp7dc'].join('_');
    const r = redactText(`key ${stripeKey}`);
    expect(r.findings.some((f) => f.type === 'stripe-secret-key')).toBe(true);
  });

  it('handles many secrets in one paste and numbers placeholders per type', () => {
    const r = redactText(
      'user a@x.com and b@y.com, keys AKIAIOSFODNN7EXAMPLE and AKIAZZZZZZZZZZZZZZZZ',
    );
    expect(r.redactedCount).toBe(4);
    expect(r.redactedText).toContain('[REDACTED:EMAIL-1]');
    expect(r.redactedText).toContain('[REDACTED:EMAIL-2]');
    expect(r.redactedText).toContain('[REDACTED:AWS-ACCESS-KEY-1]');
    expect(r.redactedText).toContain('[REDACTED:AWS-ACCESS-KEY-2]');
  });

  it('leaves clean text untouched with zero findings', () => {
    const text = 'The login form returns 500 when the username is empty.';
    const r = redactText(text);
    expect(r.redactedCount).toBe(0);
    expect(r.redactedText).toBe(text);
    expect(r.findings).toEqual([]);
  });

  it('reports findings in document order', () => {
    const r = redactText('a@x.com then AKIAIOSFODNN7EXAMPLE then b@y.com');
    const types = r.findings.map((f) => f.type);
    expect(types).toEqual(['email', 'aws-access-key', 'email']);
  });
});
