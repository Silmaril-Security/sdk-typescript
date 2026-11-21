import { performance } from 'node:perf_hooks';
const fetchRequest = globalThis.fetch;
let calls = 0;
globalThis.fetch = async (...args) => {
  calls++;
  const start = performance.now();
  try {
    const response = await fetchRequest(...args);
    console.log('Classifier call', calls, 'HTTP', response.status, 'in', Math.round(performance.now() - start), 'ms');
    return response;
  } catch (error) {
    const code = String(error.cause?.code ?? error.code ?? '');
    console.log('Transport failure', calls, /^(E[A-Z_]+|UND_ERR_[A-Z_]+)$/.test(code) ? code : 'unclassified');
    throw error;
  }
};
process.on('uncaughtException', error => {
  const name = String(error.name);
  const message = String(error.message);
  const category = [
    'Customer request was denied', 'Firewall: invalid outcome_scores', 'Firewall: invalid',
    'fetch failed', 'Firewall request failed', 'The operation was aborted',
  ].find(prefix => message.startsWith(prefix));
  console.log('Consumer stopped after', calls, 'calls', /^[A-Za-z]{1,64}$/.test(name) ? name : 'Error',
    category ?? 'unclassified');
  process.exit(1);
});
