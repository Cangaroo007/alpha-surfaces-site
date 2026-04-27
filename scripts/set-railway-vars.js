const fetch = require('node-fetch');

const RAILWAY_API = 'https://backboard.railway.app/graphql/v2';
const PROJECT_ID  = '83e36e08-4562-42ac-a39c-8111a7ceb192';
const SERVICE_ID  = '64c256bc-0b41-4485-9611-8624dab25425';

// Railway API tokens — set these as environment variables before running:
//   export RAILWAY_TOKEN_STAGING="your-staging-token"
//   export RAILWAY_TOKEN_PRODUCTION="your-production-token"
const TOKENS = {
  staging:    process.env.RAILWAY_TOKEN_STAGING,
  production: process.env.RAILWAY_TOKEN_PRODUCTION
};

// Variables to set — values loaded from environment or .env file
// Usage: Set each variable as an env var, then run this script.
// Example: export TWILIO_ACCOUNT_SID="ACxxxx" && node scripts/set-railway-vars.js
const SHARED_VARS = {
  TWILIO_ACCOUNT_SID:     process.env.TWILIO_ACCOUNT_SID || '',
  TWILIO_AUTH_TOKEN:      process.env.TWILIO_AUTH_TOKEN || '',
  TWILIO_FROM:            process.env.TWILIO_FROM || '',
  TWILIO_TO:              process.env.TWILIO_TO || '',
  ALERT_EMAIL_TO:         process.env.ALERT_EMAIL_TO || 'hello@alphasurfaces.com.au',
  SMTP_HOST:              process.env.SMTP_HOST || 'smtp.office365.com',
  SMTP_PORT:              process.env.SMTP_PORT || '587',
  SMTP_USER:              process.env.SMTP_USER || 'hello@alphasurfaces.com.au',
  SMTP_PASS:              process.env.SMTP_PASS || '',
  INSTAGRAM_ACCOUNT_ID:   process.env.INSTAGRAM_ACCOUNT_ID || '',
  INSTAGRAM_ACCESS_TOKEN: process.env.INSTAGRAM_ACCESS_TOKEN || '',
  RAILWAY_TOKEN_STAGING:    process.env.RAILWAY_TOKEN_STAGING || '',
  RAILWAY_TOKEN_PRODUCTION: process.env.RAILWAY_TOKEN_PRODUCTION || ''
};

async function gql(token, query, variables) {
  const res = await fetch(RAILWAY_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ query, variables })
  });
  const data = await res.json();
  if (data.errors) throw new Error(JSON.stringify(data.errors));
  return data.data;
}

async function getEnvironments(token) {
  const data = await gql(token, `
    query {
      project(id: "${PROJECT_ID}") {
        environments {
          edges {
            node { id name }
          }
        }
      }
    }
  `);
  return data.project.environments.edges.map(e => e.node);
}

async function upsertVar(token, environmentId, name, value) {
  await gql(token, `
    mutation UpsertVariable($input: VariableUpsertInput!) {
      variableUpsert(input: $input)
    }
  `, {
    input: {
      projectId: PROJECT_ID,
      serviceId: SERVICE_ID,
      environmentId,
      name,
      value
    }
  });
}

async function run() {
  for (const [envName, token] of Object.entries(TOKENS)) {
    if (!token) {
      console.log(`\n[${envName}] Skipped — no RAILWAY_TOKEN_${envName.toUpperCase()} set`);
      continue;
    }

    console.log(`\n[${envName}] Fetching environments...`);
    const envs = await getEnvironments(token);
    console.log(`[${envName}] Found: ${envs.map(e => e.name).join(', ')}`);

    const env = envs.find(e => e.name.toLowerCase() === envName) || envs[0];
    console.log(`[${envName}] Targeting environment: ${env.name} (${env.id})`);

    for (const [name, value] of Object.entries(SHARED_VARS)) {
      await upsertVar(token, env.id, name, value);
      console.log(`[${envName}] ✓ ${name}`);
    }
    console.log(`[${envName}] All variables set.`);
  }
}

run().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
