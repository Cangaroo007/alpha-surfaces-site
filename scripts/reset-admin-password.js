#!/usr/bin/env node
/**
 * Admin password reset utility — Alpha Surfaces CMS.
 *
 * What it does:
 *   Prompts for a new password, prints a bcrypt hash you paste into Railway
 *   as the ADMIN_PASSWORD env var. The login route in server.js accepts both
 *   bcrypt and plain text, so the hashed form keeps the cleartext out of
 *   Railway's variable history.
 *
 * Why this exists:
 *   The CMS has no in-app password reset. If you forget the password and
 *   Railway only stores a bcrypt hash, this is how you recover access.
 *
 * Usage:
 *   npm run reset-admin
 *     — prompts for the new password interactively
 *
 *   node scripts/reset-admin-password.js
 *     — same thing, direct invocation
 *
 *   echo "the-new-password" | node scripts/reset-admin-password.js --stdin
 *     — for non-interactive use; still prints the hash to stdout
 *
 * What to do with the hash:
 *   1. Open Railway → project alpha-surfaces-site → Variables tab
 *   2. Set ADMIN_PASSWORD = (the hash printed below) on BOTH the staging
 *      and production environments (otherwise only one site will accept it)
 *   3. Save — Railway redeploys (~1–2 min, ~30s downtime during boot)
 *   4. Log in at /admin.html with the cleartext password you typed
 *   5. Store the cleartext in 1Password / Bitwarden / equivalent — there is
 *      no other way to recover it.
 */

const bcrypt = require('bcryptjs');
const readline = require('readline');

const MIN_LENGTH = 12;
const COST = 12;

function getPassword() {
  if (process.argv.includes('--stdin')) {
    return new Promise((resolve, reject) => {
      let buf = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => { buf += chunk; });
      process.stdin.on('end',  ()    => resolve(buf.trim()));
      process.stdin.on('error', reject);
    });
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(`New ADMIN_PASSWORD (min ${MIN_LENGTH} chars): `, ans => {
      rl.close();
      resolve(ans);
    });
  });
}

(async () => {
  const pwd = await getPassword();
  if (!pwd || pwd.length < MIN_LENGTH) {
    console.error(`\nPassword must be at least ${MIN_LENGTH} characters. Aborting.`);
    process.exit(1);
  }
  const hash = bcrypt.hashSync(pwd, COST);
  console.log('\n────────────────────────────────────────────────────────────');
  console.log('Bcrypt hash — paste into Railway as ADMIN_PASSWORD:');
  console.log('────────────────────────────────────────────────────────────');
  console.log(hash);
  console.log('────────────────────────────────────────────────────────────');
  console.log('\nNext steps:');
  console.log('  1. Railway → alpha-surfaces-site → Variables');
  console.log('  2. Set ADMIN_PASSWORD = (hash above) on BOTH staging + production envs');
  console.log('  3. Save → Railway redeploys (~1–2 min)');
  console.log('  4. Log in at /admin.html with the cleartext password you just typed');
  console.log('  5. Store that cleartext in your password manager — no other recovery.\n');
})().catch(err => {
  console.error('Failed:', err.message);
  process.exit(1);
});
