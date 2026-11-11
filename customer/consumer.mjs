import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { Firewall, FirewallBlockedException, HookLabel } from '@silmaril-security/sdk';
const scenario = JSON.parse(readFileSync(process.env.CUSTOMER_SCENARIO, 'utf8'));
const runId = process.env.CUSTOMER_RUN_ID;
const client = new Firewall({apiKey: process.env.SILMARIL_API_KEY, apiUrl: process.env.SILMARIL_API_URL, mode: 'block'});
const user = await client.classify(scenario.user_input, {hook: HookLabel.USER_INPUT, requestId: `${runId}-user`});
if (user.prediction !== 'BENIGN' || user.governance?.action === 'block') throw new Error('Customer request was denied');
const cases = [];
for (const item of scenario.cases) {
  const requestId = `${runId}-${item.id}`;
  let blocked = false, result;
  try { result = await client.classify(item.text, {hook: HookLabel.TOOL_RESPONSE, toolName: scenario.tool_name, requestId}); }
  catch (error) {
    if (!(error instanceof FirewallBlockedException)) throw error;
    blocked = true; result = error.result;
  }
  // Direct TypeScript classification returns a decision; the customer applies it.
  blocked = blocked || ((result.mode ?? 'block') === 'block' && (result.prediction === 'MALICIOUS' || result.governance?.action === 'block'));
  const summary = `${item.id}.summary.txt`;
  if (!blocked) writeFileSync(summary, 'Search performance improved; settings fixed.\n');
  cases.push({id: item.id, request_id: requestId, prediction: result.prediction, blocked, wrote_summary: existsSync(summary)});
}
writeFileSync(process.env.CUSTOMER_RESULT, JSON.stringify({run_id: runId, cases}));
