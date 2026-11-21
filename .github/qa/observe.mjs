import { performance } from 'node:perf_hooks';
import { appendFileSync } from 'node:fs';
function note(...values) {
  appendFileSync(process.env.QA_OBSERVATIONS, values.join(' ') + '\n');
}
import { channel } from 'node:diagnostics_channel';
const sockets = new WeakMap();
let opened = 0;
channel('undici:client:connected').subscribe(({ socket }) => {
  sockets.set(socket, ++opened);
  note('Connected', opened, socket.remoteFamily, socket.remoteAddress);
});
channel('undici:client:sendHeaders').subscribe(({ socket }) => {
  note('Sent headers on connection', sockets.get(socket) ?? 'unknown');
});
channel('undici:client:connectError').subscribe(({ error }) => {
  note('Connect error', error.code);
});
const fetchRequest = globalThis.fetch;
let calls = 0;
globalThis.fetch = async (...args) => {
  calls++;
  const start = performance.now();
  try {
    const response = await fetchRequest(...args);
    note('Classifier call', calls, 'HTTP', response.status, 'in', Math.round(performance.now() - start), 'ms');
    return response;
  } catch (error) {
    const code = String(error.cause?.code ?? error.code ?? '');
    note('Transport failure', calls, /^(E[A-Z_]+|UND_ERR_[A-Z_]+)$/.test(code) ? code : 'unclassified');
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
  note('Consumer stopped after', calls, 'calls', /^[A-Za-z]{1,64}$/.test(name) ? name : 'Error',
    category ?? 'unclassified');
  process.exit(1);
});
