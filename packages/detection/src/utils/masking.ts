/**
 * Safe Preview Masking Utilities
 *
 * Generates safe, non-sensitive previews for DetectionEvidence.
 * Strictly prevents leaking full sensitive values into logs or audit metadata.
 */

export function maskEmail(email: string): string {
  const atIndex = email.indexOf('@');
  if (atIndex <= 1) {
    return '***@' + (email.slice(atIndex + 1) || 'domain.com');
  }
  const user = email.slice(0, atIndex);
  const domain = email.slice(atIndex + 1);
  const firstChar = user[0] ?? '';
  const lastChar = user.length > 2 ? (user[user.length - 1] ?? '') : '';
  return `${firstChar}***${lastChar}@${domain}`;
}

export function maskPhone(phone: string): string {
  // Preserve last 4 digits for verification, mask the rest
  const digitsOnly = phone.replace(/\D/g, '');
  if (digitsOnly.length < 4) {
    return '***-***-****';
  }
  const lastFour = digitsOnly.slice(-4);
  const hasPlus = phone.trim().startsWith('+');
  return `${hasPlus ? '+' : ''}***-***-${lastFour}`;
}

export function maskToken(token: string, prefixLen = 4, suffixLen = 4): string {
  if (token.length <= prefixLen + suffixLen) {
    return '********';
  }
  const prefix = token.slice(0, prefixLen);
  const suffix = token.slice(-suffixLen);
  return `${prefix}****${suffix}`;
}

export function maskGenericSecret(secret: string): string {
  if (secret.length <= 6) {
    return '******';
  }
  const prefix = secret.slice(0, 2);
  const suffix = secret.slice(-2);
  return `${prefix}****${suffix}`;
}
