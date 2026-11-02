import assert from 'node:assert/strict';
import { handleRequest } from '../worker/xncfbox/worker.mjs';

const uuid = '01234567-89ab-4cde-8123-456789abcdef';
const env = {
  VLESS_UUID: uuid,
  ADMIN_TOKEN: 'admin-token',
  SUB_TOKEN: 'sub-token',
  CHECKER_TOKEN: 'check-token',
  MANIFEST: {
    async get() {
      return {
        schema_version: 1,
        kind: 'vpngate_cf_validated_nodes',
        generated_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        scope: 'tcp_ipv4_ws',
        data_plane: { base_path: '/' },
        nodes: [{
          node_id: 'test-node',
          hostname: 'vpn123.opengw.net',
          country: 'US',
          sstp_host: 'vpn123.opengw.net',
          sstp_port: 443,
          expected_exit_ip: '203.0.113.10',
          actual_exit_ip: '203.0.113.10',
          verified_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600000).toISOString(),
        }],
      };
    },
  },
  __checkSstp: async () => ({ exitIp: '203.0.113.10', assignedIp: '10.0.0.2' }),
};

const request = (path, init = {}) => new Request('https://xncfbox.example' + path, init);

const health = await handleRequest(request('/health'), env);
assert.equal(health.status, 200);
const healthJson = await health.json();
assert.equal(healthJson.service, 'xncfbox');
assert.equal(healthJson.configured, true);
assert.ok(!JSON.stringify(healthJson).includes(uuid));

const unauthorized = await handleRequest(request('/check?proxy=sstp%3A%2F%2Fvpn%3Avpn%40vpn123.opengw.net%3A443'), env);
assert.equal(unauthorized.status, 401);

const checked = await handleRequest(request('/check?proxy=sstp%3A%2F%2Fvpn%3Avpn%40vpn123.opengw.net%3A443', {
  headers: { Authorization: 'Bearer check-token' },
}), env);
assert.equal(checked.status, 200);
assert.equal((await checked.json()).success, true);

const subscription = await handleRequest(request('/sub?token=sub-token'), env);
assert.equal(subscription.status, 200);
const encoded = await subscription.text();
assert.ok(encoded.length > 20);

const admin = await handleRequest(request('/admin'), env);
assert.equal(admin.status, 200);
assert.ok((await admin.text()).includes('xncfbox'));

const unknownNode = await handleRequest(request('/?sstp=vpn%3Avpn%40other123.opengw.net%3A443&globalproxy=1', {
  headers: { Upgrade: 'websocket' },
}), env);
assert.equal(unknownNode.status, 403);

console.log('xncfbox worker checks passed');
