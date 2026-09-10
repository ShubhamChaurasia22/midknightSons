import { describe, it, expect } from 'vitest';
import {
  EmailDetector,
  PhoneDetector,
  ApiKeyDetector,
  PasswordDetector,
  GenericSecretDetector,
  createDefaultDetectorRegistry,
  resolveOverlaps,
  deduplicateExactRanges,
} from '../packages/detection/src';
import type { DetectionEntity } from '@shield/core';

describe('M1.2 Shield Detection Engine', () => {
  describe('1. EmailDetector', () => {
    const detector = new EmailDetector();

    it('detects standard valid email addresses', async () => {
      const text = 'Contact me at john.doe@example.com for support.';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(1);
      const email = results[0]!;
      expect(email.category).toBe('PII');
      expect(email.severity).toBe('MEDIUM');
      expect(email.confidence).toBe(0.95);
      expect(email.detectorId).toBe('detector-email');

      // Exact range verification
      expect(text.slice(email.range.startIndex, email.range.endIndex)).toBe('john.doe@example.com');
    });

    it('detects multiple emails embedded in prose', async () => {
      const text = 'Admins are alice@company.org and bob.smith+dev@sub.domain.co.uk.';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        'alice@company.org',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        'bob.smith+dev@sub.domain.co.uk',
      );
    });

    it('rejects invalid email formats or non-email code symbols', async () => {
      const invalidTexts = [
        'user@localhost', // No valid TLD
        'test@@example.com', // Double @
        '123@456', // No domain TLD
        'decorator @Component on class', // TypeScript decorator
        'matrix multiplication A @ B', // Python operator
      ];

      for (const text of invalidTexts) {
        const results = await detector.detect({ text });
        expect(results).toHaveLength(0);
      }
    });

    it('provides safe evidence without exposing raw email', async () => {
      const text = 'Email: secret-agent@domain.com';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(1);
      const entity = results[0]!;
      expect(entity.evidence.previewMasked).toBe('s***t@domain.com');
      expect(entity.evidence.tokenLength).toBe('secret-agent@domain.com'.length);
      expect(entity.evidence.hasRawValue).toBe(false);
      expect(entity.rawValue).toBeUndefined();
    });
  });

  describe('2. PhoneDetector', () => {
    const detector = new PhoneDetector();

    it('detects international phone numbers with + prefix', async () => {
      const text = 'Call our global hotline at +1-555-555-5555 or UK line +44 20 7946 0958 today.';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(results[0]!.category).toBe('PII');
      expect(results[0]!.confidence).toBe(0.95);
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        '+1-555-555-5555',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        '+44 20 7946 0958',
      );
    });

    it('detects formatted North American local phone numbers', async () => {
      const text = 'Reach me at (555) 123-4567 or on my cell 555-987-6543 or office 555.333.2222.';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(3);
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        '(555) 123-4567',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        '555-987-6543',
      );
      expect(text.slice(results[2]!.range.startIndex, results[2]!.range.endIndex)).toBe(
        '555.333.2222',
      );
    });

    it('does NOT treat arbitrary long numbers or dates as phone numbers', async () => {
      const nonPhoneTexts = [
        'Order number is 123456789012345',
        'Release date was 2026-09-11 in Tokyo',
        'Calculated 100 - 50 = 50 in notebook',
        'Epoch timestamp is 1726000000000',
        'Short code 12345 is not a phone',
      ];

      for (const text of nonPhoneTexts) {
        const results = await detector.detect({ text });
        expect(results).toHaveLength(0);
      }
    });

    it('provides safe masked phone preview', async () => {
      const text = 'Phone: +1-555-123-4567';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(1);
      expect(results[0]!.evidence.previewMasked).toBe('+***-***-4567');
      expect(results[0]!.evidence.hasRawValue).toBe(false);
      expect(results[0]!.rawValue).toBeUndefined();
    });
  });

  describe('3. ApiKeyDetector', () => {
    const detector = new ApiKeyDetector();

    it('detects OpenAI API keys (standard and proj-scoped)', async () => {
      const text =
        'Keys: sk-abcdef1234567890abcdef123456 and sk-proj-1234567890abcdef1234567890abcdef.';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(results[0]!.category).toBe('API_KEY');
      expect(results[0]!.severity).toBe('CRITICAL');
      expect(results[0]!.confidence).toBe(0.99);
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        'sk-abcdef1234567890abcdef123456',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        'sk-proj-1234567890abcdef1234567890abcdef',
      );
    });

    it('detects GitHub tokens and AWS access key IDs', async () => {
      const text =
        'export GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234 && AWS_KEY=AKIAIOSFODNN7EXAMPLE';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        'ghp_1234567890abcdef1234567890abcdef1234',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        'AKIAIOSFODNN7EXAMPLE',
      );
    });

    it('detects Slack tokens and Bearer auth headers', async () => {
      const text =
        'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and slack=xoxb-1234567890-1234567890123-abc';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(results[0]!.evidence.ruleName).toBe('bearer-token');
      expect(results[1]!.evidence.ruleName).toBe('slack-token');
    });

    it('rejects too-short or invalid tokens', async () => {
      const text = 'The sk-short is not valid nor is AKIA123';
      const results = await detector.detect({ text });
      expect(results).toHaveLength(0);
    });

    it('masks token preview securely', async () => {
      const text = 'sk-proj-1234567890abcdef1234567890abcdef';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(1);
      const preview = results[0]!.evidence.previewMasked;
      expect(preview).toBe('sk-p****cdef');
      expect(results[0]!.rawValue).toBeUndefined();
    });
  });

  describe('4. PasswordDetector', () => {
    const detector = new PasswordDetector();

    it('detects passwords in explicit assignment structures', async () => {
      const text = 'Set password="SuperSecretPassword#2026" or passwd: MyDatabaseSecret42';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(results[0]!.category).toBe('PASSWORD');
      expect(results[0]!.severity).toBe('HIGH');
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        'SuperSecretPassword#2026',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        'MyDatabaseSecret42',
      );
    });

    it('does NOT trigger on bare word "password" in ordinary prose', async () => {
      const proseTexts = [
        'Please enter a strong password during signup.',
        'The password policy requires 12 characters.',
        'Forgot your password? Click here to reset it.',
        'Users should not share their passwords with colleagues.',
      ];

      for (const text of proseTexts) {
        const results = await detector.detect({ text });
        expect(results).toHaveLength(0);
      }
    });

    it('ignores code placeholders and dummy passwords', async () => {
      const dummyText = 'password=null and passwd=placeholder and pwd=changeme';
      const results = await detector.detect({ text: dummyText });
      expect(results).toHaveLength(0);
    });
  });

  describe('5. GenericSecretDetector', () => {
    const detector = new GenericSecretDetector();

    it('detects assigned access tokens and client secrets', async () => {
      const text =
        'client_secret: "9f8a7b6c5d4e3f2a1b0c9d8e" and access_token=sec_tok_abcdef123456789';
      const results = await detector.detect({ text });

      expect(results).toHaveLength(2);
      expect(results[0]!.category).toBe('SECRET');
      expect(results[0]!.severity).toBe('HIGH');
      expect(text.slice(results[0]!.range.startIndex, results[0]!.range.endIndex)).toBe(
        '9f8a7b6c5d4e3f2a1b0c9d8e',
      );
      expect(text.slice(results[1]!.range.startIndex, results[1]!.range.endIndex)).toBe(
        'sec_tok_abcdef123456789',
      );
    });

    it('does NOT trigger on ordinary prose containing words "secret" or "token"', async () => {
      const proseTexts = [
        'It was a secret garden filled with rare flowers.',
        'He gave her a small token of appreciation for her help.',
        'Keep this secret between us.',
      ];

      for (const text of proseTexts) {
        const results = await detector.detect({ text });
        expect(results).toHaveLength(0);
      }
    });
  });

  describe('6. Overlap & Duplicate Resolution', () => {
    it('deduplicates exact ranges keeping highest severity', () => {
      const duplicateEntities: DetectionEntity[] = [
        {
          id: '1',
          detectorId: 'detector-low',
          category: 'PII',
          severity: 'LOW',
          confidence: 0.8,
          range: { startIndex: 10, endIndex: 25 },
          evidence: { tokenLength: 15, hasRawValue: false },
        },
        {
          id: '2',
          detectorId: 'detector-high',
          category: 'API_KEY',
          severity: 'CRITICAL',
          confidence: 0.99,
          range: { startIndex: 10, endIndex: 25 },
          evidence: { tokenLength: 15, hasRawValue: false },
        },
      ];

      const resolved = deduplicateExactRanges(duplicateEntities);
      expect(resolved).toHaveLength(1);
      expect(resolved[0]!.severity).toBe('CRITICAL');
      expect(resolved[0]!.category).toBe('API_KEY');
    });

    it('resolves overlapping ranges keeping highest severity', () => {
      const overlapping: DetectionEntity[] = [
        {
          id: 'outer',
          detectorId: 'detector-password',
          category: 'PASSWORD',
          severity: 'HIGH',
          confidence: 0.85,
          range: { startIndex: 0, endIndex: 35 },
          evidence: { tokenLength: 35, hasRawValue: false },
        },
        {
          id: 'inner',
          detectorId: 'detector-api-key',
          category: 'API_KEY',
          severity: 'CRITICAL',
          confidence: 0.99,
          range: { startIndex: 9, endIndex: 35 },
          evidence: { tokenLength: 26, hasRawValue: false },
        },
      ];

      const resolved = resolveOverlaps(overlapping, 'KEEP_HIGHEST_SEVERITY');
      expect(resolved).toHaveLength(1);
      expect(resolved[0]!.severity).toBe('CRITICAL');
      expect(resolved[0]!.id).toBe('inner');
    });
  });

  describe('7. Detector Registry Operations & Batch Run', () => {
    it('registers, retrieves, and filters detectors correctly', () => {
      const registry = createDefaultDetectorRegistry();
      expect(registry.getAll()).toHaveLength(5);

      const piiDetectors = registry.getByCategory('PII');
      expect(piiDetectors).toHaveLength(2); // Email, Phone

      const emailDetector = registry.get('detector-email');
      expect(emailDetector).toBeDefined();

      const unregistered = registry.unregister('detector-phone');
      expect(unregistered).toBe(true);
      expect(registry.getAll()).toHaveLength(4);
    });

    it('runs all detectors concurrently and aggregates findings', async () => {
      const registry = createDefaultDetectorRegistry();
      const prompt = `
        Hello AI! Here is my account setup:
        Email: developer@shield-security.com
        Phone: +1-555-432-1098
        API Key: sk-proj-1234567890abcdef1234567890abcdef
        DB Secret: password="SuperSecureDatabasePassword!#42"
      `;

      const result = await registry.runAll({ text: prompt });
      expect(result.hasDetections).toBe(true);
      expect(result.entities).toHaveLength(4);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);

      // Verify categories found
      const categories = result.entities.map((e) => e.category);
      expect(categories).toContain('PII');
      expect(categories).toContain('API_KEY');
      expect(categories).toContain('PASSWORD');

      // Verify zero raw values exposed in evidence
      for (const entity of result.entities) {
        expect(entity.evidence.hasRawValue).toBe(false);
        expect(entity.rawValue).toBeUndefined();
        expect(entity.evidence.previewMasked).toBeDefined();
      }
    });

    it('returns empty result cleanly for blank input', async () => {
      const registry = createDefaultDetectorRegistry();
      const result = await registry.runAll({ text: '' });
      expect(result.hasDetections).toBe(false);
      expect(result.entities).toHaveLength(0);
    });
  });

  describe('8. Edge Cases & Unicode Handling', () => {
    const registry = createDefaultDetectorRegistry();

    it('preserves accurate ranges with emojis and multi-byte characters', async () => {
      const prompt = '🔒 Security notification: email test@example.com was verified ✅';
      const result = await registry.runAll({ text: prompt });

      expect(result.hasDetections).toBe(true);
      expect(result.entities).toHaveLength(1);

      const match = result.entities[0]!;
      expect(prompt.slice(match.range.startIndex, match.range.endIndex)).toBe('test@example.com');
    });
  });

  describe('9. Security & Non-leakage Guarantees', () => {
    it('ensures serialized diagnostics/output never contain raw secret values', async () => {
      const registry = createDefaultDetectorRegistry();
      const rawSecret = 'sk-proj-SUPERSECRETKEY1234567890ABCDEF123456';
      const rawPassword = 'UltraConfidentialPassword#999';
      const text = `Keys: ${rawSecret} and password=${rawPassword}`;

      const result = await registry.runAll({ text });
      expect(result.entities.length).toBeGreaterThanOrEqual(2);

      // Verify serialized output (such as would be sent to logs or diagnostics) does not leak raw values
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(rawSecret);
      expect(serialized).not.toContain(rawPassword);

      // Verify each entity's rawValue is undefined and hasRawValue is false
      for (const entity of result.entities) {
        expect(entity.rawValue).toBeUndefined();
        expect(entity.evidence.hasRawValue).toBe(false);
        // Previews must be properly masked
        if (entity.evidence.previewMasked) {
          expect(entity.evidence.previewMasked).toContain('*');
          expect(entity.evidence.previewMasked).not.toBe(rawSecret);
          expect(entity.evidence.previewMasked).not.toBe(rawPassword);
        }
      }
    });
  });
});
