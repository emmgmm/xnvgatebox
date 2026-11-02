// Self-hosted TCP-only VLESS over WebSocket to VPN Gate SSTP.
// This module is an independent implementation of the protocol boundary used
// by xncfbox. It does not import or forward to another Worker.

const EMPTY = new Uint8Array(0);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NODE_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.opengw\.net$/i;

let connectorPromise;
async function socketConnect() {
  if (!connectorPromise) {
    connectorPromise = import('cloudflare:sockets').then(mod => mod.connect);
  }
  return connectorPromise;
}

function concat(...chunks) {
  const parts = chunks.filter(chunk => chunk && chunk.byteLength);
  const output = new Uint8Array(parts.reduce((n, part) => n + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.byteLength; }
  return output;
}

function u16(bytes, at = 0) { return (bytes[at] << 8) | bytes[at + 1]; }
function u32(bytes, at = 0) { return ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0; }
function put16(view, at, value) { view.setUint16(at, value & 0xffff); }
function put32(view, at, value) { view.setUint32(at, value >>> 0); }
function timeout(promise, ms, message) {
  let timer;
  const expiry = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

function checksum(bytes, offset, length) {
  let sum = 0;
  for (let i = offset; i + 1 < offset + length; i += 2) sum += u16(bytes, i);
  if (length & 1) sum += bytes[offset + length - 1] << 8;
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

function pppConfigure(protocol, code, id, options = []) {
  const size = options.reduce((n, option) => n + option.data.byteLength + 2, 0);
  const frame = new Uint8Array(6 + size);
  const view = new DataView(frame.buffer);
  put16(view, 0, protocol); frame[2] = code; frame[3] = id; put16(view, 4, 4 + size);
  let at = 6;
  for (const option of options) { frame[at] = option.type; frame[at + 1] = option.data.byteLength + 2; frame.set(option.data, at + 2); at += option.data.byteLength + 2; }
  return frame;
}

function sstpPacket(ppp) {
  const length = 6 + ppp.byteLength;
  const packet = new Uint8Array(length);
  packet.set([0x10, 0x00, 0x80 | ((length >>> 8) & 0x0f), length & 0xff, 0xff, 0x03]);
  packet.set(ppp, 6);
  return packet;
}

function parsePpp(data) {
  let at = data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
  if (data.byteLength < at + 4) return null;
  const protocol = u16(data, at);
  if (protocol === 0x0021) return { protocol, ip: data.subarray(at + 2) };
  if (data.byteLength < at + 6) return null;
  return { protocol, code: data[at + 2], id: data[at + 3], body: data.subarray(at + 6), raw: data.subarray(at) };
}

function pppOptions(body) {
  const result = [];
  for (let at = 0; at + 2 <= body.byteLength;) {
    const length = body[at + 1];
    if (length < 2 || at + length > body.byteLength) break;
    result.push({ type: body[at], data: body.subarray(at + 2, at + length) });
    at += length;
  }
  return result;
}

async function openSstp(proxy, targetHost, targetPort) {
  if (!proxy || !NODE_RE.test(proxy.hostname) || !Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535) throw new Error('invalid_sstp_backend');
  const connect = await socketConnect();
  const socket = connect({ hostname: proxy.hostname, port: proxy.port }, { secureTransport: 'on', allowHalfOpen: false });
  await timeout(socket.opened, 12000, 'sstp_connect_timeout');
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let buffered = EMPTY;
  let closed = false;
  let phase = 'connect';
  const close = () => { if (closed) return; closed = true; try { reader.cancel(); } catch {} try { writer.close(); } catch {} try { socket.close(); } catch {} };
  const readChunk = async () => { const item = await reader.read(); if (item.done || !item.value) throw new Error('sstp_closed'); return new Uint8Array(item.value); };
  const readBytes = async size => { while (buffered.byteLength < size) buffered = concat(buffered, await readChunk()); const out = buffered.subarray(0, size); buffered = buffered.subarray(size); return out; };
  const readLine = async () => { for (;;) { const at = buffered.indexOf(10); if (at >= 0) { const line = decoder.decode(buffered.subarray(0, at)).replace(/\r$/, ''); buffered = buffered.subarray(at + 1); return line; } buffered = concat(buffered, await readChunk()); } };
  const readPacket = async () => { const head = await timeout(readBytes(4), 12000, 'sstp_packet_timeout'); const length = u16(head, 2) & 0x0fff; if (length < 4 || length > 8192) throw new Error('sstp_packet_invalid'); return { control: (head[1] & 1) !== 0, body: length > 4 ? await timeout(readBytes(length - 4), 12000, 'sstp_packet_body_timeout') : EMPTY }; };

  try {
    phase = 'http_handshake';
    const host = proxy.port === 443 ? proxy.hostname : `${proxy.hostname}:${proxy.port}`;
    const request = encoder.encode(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`);
    const control = new Uint8Array(14); control.set([0x10, 0x01, 0x80, 0x0e, 0, 1, 0, 1, 0, 1, 0, 6, 0, 1]);
    const lcp = sstpPacket(pppConfigure(0xc021, 1, 1, [{ type: 1, data: new Uint8Array([0x05, 0xdc]) }]));
    await timeout(writer.write(concat(request, control, lcp)), 12000, 'sstp_handshake_timeout');
    const status = await timeout(readLine(), 12000, 'sstp_http_timeout');
    for (;;) { if ((await timeout(readLine(), 12000, 'sstp_headers_timeout')) === '') break; }
    if (!/^HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(status)) throw new Error('sstp_http_rejected');

    phase = 'ppp_handshake';
    let nextId = 2, localAck = false, peerAck = false, needsPap = false, papSent = false, papDone = false, ipcpStarted = false, ipcpDone = false, assignedIp = null;
    const sendPapIfReady = async () => {
      if (!localAck || !peerAck || !needsPap || papSent) return;
      const user = encoder.encode(proxy.username || ''), pass = encoder.encode(proxy.password || '');
      if (user.byteLength > 255 || pass.byteLength > 255) throw new Error('sstp_auth_too_long');
      const pap = new Uint8Array(8 + user.byteLength + pass.byteLength);
      const view = new DataView(pap.buffer);
      put16(view, 0, 0xc023); pap[2] = 1; pap[3] = nextId++;
      put16(view, 4, pap.byteLength - 2); pap[6] = user.byteLength; pap.set(user, 7);
      pap[7 + user.byteLength] = pass.byteLength; pap.set(pass, 8 + user.byteLength);
      await writer.write(sstpPacket(pap)); papSent = true;
    };
    const startIpcpIfReady = async () => {
      if (!localAck || !peerAck || ipcpStarted || (needsPap && !papDone)) return;
      await writer.write(sstpPacket(pppConfigure(0x8021, 1, nextId++, [{ type: 3, data: new Uint8Array(4) }])));
      ipcpStarted = true;
    };
    for (let rounds = 0; rounds < 60 && !ipcpDone; rounds++) {
      phase = `ppp_round_${rounds}`;
      const packet = await readPacket(); if (packet.control) continue;
      const frame = parsePpp(packet.body); if (!frame) continue;
      if (frame.protocol === 0xc021) {
        if (frame.code === 1) {
          const auth = pppOptions(frame.body).find(x => x.type === 3)?.data;
          if (auth?.byteLength >= 2) {
            if (u16(auth) !== 0xc023) throw new Error('sstp_auth_unsupported');
            needsPap = true;
          }
          const ack = new Uint8Array(frame.raw); ack[2] = 2; await writer.write(sstpPacket(ack)); peerAck = true;
        } else if (frame.code === 2) localAck = true;
        await sendPapIfReady(); await startIpcpIfReady();
      } else if (frame.protocol === 0xc023) {
        if (frame.code === 3) throw new Error('sstp_auth_failed');
        if (frame.code === 2) papDone = true;
        await startIpcpIfReady();
      } else if (frame.protocol === 0x8021) {
        if (frame.code === 1) { const ack = new Uint8Array(frame.raw); ack[2] = 2; await writer.write(sstpPacket(ack)); await startIpcpIfReady(); }
        if (frame.code === 3) { const address = pppOptions(frame.body).find(x => x.type === 3)?.data; if (address?.byteLength === 4) { assignedIp = [...address].join('.'); await writer.write(sstpPacket(pppConfigure(0x8021, 1, nextId++, [{ type: 3, data: address }]))); ipcpStarted = true; } }
        if (frame.code === 2) { const address = pppOptions(frame.body).find(x => x.type === 3)?.data; if (address?.byteLength === 4) assignedIp = [...address].join('.'); if (assignedIp) ipcpDone = true; }
      }
      await sendPapIfReady(); await startIpcpIfReady();
    }
    if (!assignedIp) throw new Error('sstp_no_ipv4');
    phase = 'tcp_handshake';
    const destination = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(targetHost) ? targetHost : (await resolveV4(targetHost));
    if (!destination) throw new Error('target_ipv4_unavailable');
    let sequence = u32(crypto.getRandomValues(new Uint8Array(4))), acknowledge = 0;
    const sourcePort = 10000 + (u16(crypto.getRandomValues(new Uint8Array(2))) % 50000);
    const tcpFrame = (flags, payload = EMPTY) => {
      const ipLength = 20 + 20 + payload.byteLength, total = 8 + ipLength, out = new Uint8Array(total), view = new DataView(out.buffer);
      out.set([0x10, 0, 0x80 | ((total >>> 8) & 0x0f), total & 0xff, 0xff, 3, 0, 0x21, 0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]);
      out.set(assignedIp.split('.').map(Number), 20); out.set(destination.split('.').map(Number), 24); put16(view, 10, ipLength); put16(view, 18, checksum(out, 8, 20));
      put16(view, 28, sourcePort); put16(view, 30, targetPort); put32(view, 32, sequence); put32(view, 36, acknowledge); out[40] = 0x50; out[41] = flags; put16(view, 42, 65535); out.set(payload, 48);
      const pseudo = new Uint8Array(12 + 20 + payload.byteLength); pseudo.set(out.subarray(20, 28)); pseudo[9] = 6; pseudo[10] = (20 + payload.byteLength) >>> 8; pseudo[11] = (20 + payload.byteLength) & 0xff; pseudo.set(out.subarray(28), 12); put16(new DataView(out.buffer), 44, checksum(pseudo, 0, pseudo.byteLength)); return out;
    };
    await writer.write(tcpFrame(2)); sequence = (sequence + 1) >>> 0;
    let ready = false;
    for (let i = 0; i < 40; i++) { const packet = await readPacket(); if (packet.control) continue; const f = parsePpp(packet.body); if (!f || f.protocol !== 0x0021 || f.ip.byteLength < 40) continue; const ipAt = (f.ip[0] & 15) * 4, flags = f.ip[ipAt + 13]; if (u16(f.ip, ipAt) !== targetPort || u16(f.ip, ipAt + 2) !== sourcePort || (flags & 0x12) !== 0x12) continue; acknowledge = (u32(f.ip, ipAt + 4) + 1) >>> 0; await writer.write(tcpFrame(0x10)); ready = true; break; }
    if (!ready) throw new Error('sstp_tcp_timeout');
    phase = 'target_io';
    const read = async () => { for (;;) { const packet = await readPacket(); if (packet.control) continue; const f = parsePpp(packet.body); if (!f || f.protocol !== 0x0021 || f.ip.byteLength < 40) continue; const ipAt = (f.ip[0] & 15) * 4, tcpAt = ipAt; if (u16(f.ip, tcpAt) !== targetPort || u16(f.ip, tcpAt + 2) !== sourcePort) continue; const header = ((f.ip[tcpAt + 12] >> 4) & 15) * 4, payload = f.ip.subarray(ipAt + header); if (payload.byteLength) { acknowledge = (u32(f.ip, tcpAt + 4) + payload.byteLength) >>> 0; await writer.write(tcpFrame(0x10)); return payload; } if (f.ip[tcpAt + 13] & 1) { await writer.write(tcpFrame(0x11)); return null; } } };
    const write = async payload => { const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload); for (let at = 0; at < bytes.byteLength; at += 1300) { const part = bytes.subarray(at, Math.min(at + 1300, bytes.byteLength)); await writer.write(tcpFrame(0x18, part)); sequence = (sequence + part.byteLength) >>> 0; } };
    return { readable: { read }, writable: { write }, assignedIp, close };
  } catch (error) { close(); throw new Error(`${phase}:${error?.message || 'sstp_failed'}`); }
}

async function resolveV4(host) {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return host;
  try { const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: 'application/dns-json' } }); const json = await response.json(); return json.Answer?.find(item => item.type === 1)?.data || null; } catch { return null; }
}

export function parseVless(bytes, uuid) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 24 || !UUID_RE.test(uuid)) throw new Error('invalid_vless_request');
  const expected = uuid.replaceAll('-', '').match(/../g).map(x => Number.parseInt(x, 16)); for (let i = 0; i < 16; i++) if (bytes[i + 1] !== expected[i]) throw new Error('invalid_vless_uuid');
  const optionLength = bytes[17], commandAt = 18 + optionLength; if (bytes.byteLength < commandAt + 4 || bytes[commandAt] !== 1) throw new Error('tcp_only');
  const port = u16(bytes, commandAt + 1), type = bytes[commandAt + 3]; let at = commandAt + 4, host;
  if (type === 1) { if (bytes.byteLength < at + 4) throw new Error('invalid_ipv4'); host = [...bytes.subarray(at, at + 4)].join('.'); at += 4; }
  else if (type === 2) { const size = bytes[at++]; if (bytes.byteLength < at + size) throw new Error('invalid_domain'); host = decoder.decode(bytes.subarray(at, at + size)); at += size; }
  else if (type === 3) { if (bytes.byteLength < at + 16) throw new Error('ipv6_not_supported'); throw new Error('ipv6_not_supported'); }
  else throw new Error('invalid_address_type');
  if (!host || port < 1 || port > 65535) throw new Error('invalid_target');
  return { version: bytes[0], host, port, initial: bytes.subarray(at) };
}

export async function checkSstp(proxy) {
  // Use a plain HTTP IP echo so this single Worker does not need a second TLS
  // implementation inside the SSTP data path. Full-chain verification still
  // performs the HTTPS checks through the VLESS data plane.
  const tunnel = await openSstp(proxy, 'api.ipify.org', 80);
  try {
    try {
      await tunnel.writable.write(encoder.encode('GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n'));
      let data = EMPTY;
      for (let i = 0; i < 8 && data.byteLength < 8192; i += 1) {
        const item = await timeout(tunnel.readable.read(), 12000, 'exit_read_timeout');
        if (!item) break;
        data = concat(data, new Uint8Array(item));
        const text = decoder.decode(data);
        const match = text.match(/\{\s*"ip"\s*:\s*"([^\"]+)"\s*\}/);
        if (match) return { exitIp: match[1], assignedIp: tunnel.assignedIp };
      }
    } catch (error) { throw new Error(`ip_echo:${error?.message || 'failed'}`); }
    finally { tunnel.close(); }
    throw new Error('exit_ip_unavailable');
  } finally { tunnel.close(); }
}

export async function handleVlessWebSocket(request, env, proxy) {
  const pair = new WebSocketPair(); const client = pair[0], server = pair[1]; server.accept(); server.binaryType = 'arraybuffer';
  let opened = false, tunnel = null, pumping = false;
  const fail = () => { try { server.close(); } catch {} try { tunnel?.close(); } catch {} };
  const pump = async () => {
    if (pumping) return;
    pumping = true;
    try {
      while (tunnel && server.readyState === WebSocket.OPEN) {
        const chunk = await tunnel.readable.read();
        if (!chunk) break;
        if (chunk.byteLength) server.send(chunk);
      }
    } catch { fail(); }
  };
  const consume = async data => {
    try {
      let bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      if (!opened) {
        const requestInfo = parseVless(bytes, String(env.VLESS_UUID || ''));
        const backend = new URL(`sstp://${proxy}`);
        tunnel = await openSstp({ hostname: backend.hostname, port: Number(backend.port || 443), username: decodeURIComponent(backend.username), password: decodeURIComponent(backend.password) }, requestInfo.host, requestInfo.port);
        opened = true;
        server.send(new Uint8Array([requestInfo.version, 0]));
        void pump();
        if (requestInfo.initial.byteLength) await tunnel.writable.write(requestInfo.initial);
      } else if (tunnel) await tunnel.writable.write(bytes);
    } catch { fail(); }
  };
  server.addEventListener('message', event => { consume(event.data); }); server.addEventListener('close', () => { try { tunnel?.close(); } catch {} });
  return new Response(null, { status: 101, webSocket: client });
}
