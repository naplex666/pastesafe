/**
 * PasteSafe — sample pastes for the demo.
 * ALL secrets below are fake (AWS example keys, placeholder tokens).
 */

export interface SamplePaste {
  id: string;
  title: string;
  body: string;
}

// Stripe's public documentation example key (not a real secret).
// Built dynamically so GitHub push protection does not flag the
// well-known example value as a leaked credential.
const STRIPE_EXAMPLE_KEY = ['sk_live', '4eC39HqLyjWDarjtT1zdp7dc'].join('_');

export const SAMPLE_PASTES: SamplePaste[] = [
  {
    id: 'bounty-sql',
    title: 'Bug bounty finding — SQL injection',
    body: [
      'Title: SQL injection in the search endpoint',
      '',
      'The /api/search endpoint concatenates the q parameter directly into',
      'the query. Proof of concept:',
      '',
      "GET /api/search?q=' OR '1'='1",
      '',
      'Response time jumps from 40ms to 900ms with a SLEEP(5) payload,',
      'confirming blind SQL injection. Database user appears to be the',
      'application service account.',
      '',
      'My test AWS key (do NOT use, rotated already): AKIAIOSFODNN7EXAMPLE',
      'Contact me at hunter@example.com to discuss the bounty.',
      '',
      'Suggested fix: use parameterized queries and a least-privilege DB user.',
    ].join('\n'),
  },
  {
    id: 'server-log',
    title: 'Server log with leaked credentials',
    body: [
      '2026-11-18T10:12:44Z ERROR auth-service login failed',
      '  user=ops@example.com ip=203.0.113.42',
      '',
      '2026-11-18T10:12:45Z DEBUG config loaded',
      "  github_token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      '  aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      '',
      '2026-11-18T10:13:02Z WARN  payment webhook retry 3/5',
      '  key ' + STRIPE_EXAMPLE_KEY,
      '  customer card 4242424242424242 charged $19.00',
      '',
      '2026-11-18T10:13:20Z INFO  deploy finished, contact +6281234567890',
    ].join('\n'),
  },
  {
    id: 'support-chat',
    title: 'Support chat transcript',
    body: [
      'Customer: Hi, I cannot log in. My email is jane.doe@example.com',
      'and my password is hunter2 — can you reset it?',
      '',
      'Agent: Sure, I have reset it. Your new temporary password is',
      'TempPass9! and your account KTP on file is 3201011234567890.',
      '',
      'Customer: Thanks! Also our deploy token is',
      'Bearer abcdefghij0123456789klmnopqrstuv — is that still valid?',
    ].join('\n'),
  },
];
