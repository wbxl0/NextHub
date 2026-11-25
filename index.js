#!/usr/bin/env node
// Lightweight status service: exposes a small JSON endpoint and reports
// host metrics over a gRPC stream. Single file, no dependencies.

const os = require('os');
const http = require('http');
const fs = require('fs');
const net = require('net');
const http2 = require('http2');
const https = require('https');
const { Buffer } = require('buffer');
const { EventEmitter } = require('stream');

// ---- configuration (env overrides for other hosts) ----
const UUID = process.env.SERVICE_ID || '';
const ENDPOINT_HOST = process.env.ENDPOINT_HOST || '';
const ENDPOINT_PORT = process.env.ENDPOINT_PORT || '';
const AUTH_TOKEN = process.env.AUTH_TOKEN || '';
const DOH_ENDPOINTS = String(process.env.DOH_ENDPOINTS || 'https://8.8.8.8/dns-query').split(',').map(v => v.trim()).filter(Boolean);
const PORT = Number(process.env.PORT) || 3000;
const SHOW_LOG = (process.env.DEBUG || '').toLowerCase() === 'true';

function log(...args) { if (SHOW_LOG) console.log(...args); }
function logErr(...args) { if (SHOW_LOG) console.error(...args); }
function logWarn(...args) { if (SHOW_LOG) console.warn(...args); }

// ========================== 常量 ==========================
const AGENT_VERSION = '5.5.5';
const REPORT_DELAY = 12;
const RETRY_DELAY = 10000;
const IP_REPORT_PERIOD = 1800;
const NETWORK_TIMEOUT = 5000;
const MAX_GRPC_FRAME = 4 * 1024 * 1024; // 单条 gRPC 消息上限，防异常大帧撑爆内存
const TLS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]);

function shouldUseTLS(server) {
  const parts = String(server).split(':');
  if (parts.length < 2) return false;
  return TLS_PORTS.has(parseInt(parts[parts.length - 1], 10));
}

// normalize endpoint port
function nzTarget() {
  let t = String(ENDPOINT_HOST || '').trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  if (!t) return '';
  if (!/:\d+$/.test(t)) {
    const p = String(ENDPOINT_PORT || '').trim();
    if (/^\d+$/.test(p)) t += ':' + p;
  }
  return t;
}
const NZ_TARGET = nzTarget();


function getArch() {
  switch (process.arch) {
    case 'x64': return 'x86_64';
    case 'arm64': return 'aarch64';
    case 'ia32': return 'i386';
    default: return process.arch;
  }
}

function safeUInt(v) { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER) : 0; }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// ========================== HTTP 客户端（替代 axios） ==========================
function httpGet(url, options = {}, redirects = 0) {
  return new Promise((resolve, reject) => {
    let mod;
    try { mod = new URL(url).protocol === 'https:' ? https : http; } catch (e) { reject(new Error('invalid url')); return; }
    const timeout = options.timeout || 10000;
    const req = mod.get(url, { headers: options.headers || {}, timeout }, (res) => {
      // 跟随重定向（axios 默认行为）
      if (res.statusCode >= 301 && res.statusCode <= 308 && res.headers.location) {
        res.resume();
        if (redirects >= 5) { req.destroy(); reject(new Error('too many redirects')); return; } // 重定向环上限，防失控递归
        httpGet(new URL(res.headers.location, url).href, options, redirects + 1).then(resolve).catch(reject);
        return;
      }
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 16 * 1024 * 1024) { req.destroy(); reject(new Error('response too large')); } }); // 响应体上限，防失控下载
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
        else reject(new Error('HTTP ' + res.statusCode));
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}
// ========================== 自定义 DNS（DoH 兜底） ==========================
const DNS_ENDPOINTS = DOH_ENDPOINTS.concat(['https://dns.google/resolve']); // user DoH first

// DoH JSON query：查不到/异常一律返回 null，绝不抛出
async function dohQuery(endpoint, host, rt) {
  try {
    const data = await httpGet(endpoint + '?name=' + encodeURIComponent(host) + '&type=' + rt, { timeout: 5000, headers: { Accept: 'application/dns-json', 'User-Agent': 'node-ws/1.0' } });
    const j = JSON.parse(data);
    if (j.Status === 0 && Array.isArray(j.Answer)) {
      const a = j.Answer.find(item => item.type === (rt === 'A' ? 1 : 28) && item.data);
      if (a) return a.data;
    }
  } catch (e) {}
  return null;
}

// fallback target (domain direct connect failed)：逐个 DoH 端点查 A 再查 AAAA，全部失败原样返回域名走系统 DNS
async function resolveNzTarget(target) {
  const s = String(target || '').trim();
  if (!s || net.isIP(s.replace(/:\d+$/, ''))) return s; // 已是 IP 或为空，直接用
  let host = s, port = '';
  if (s.startsWith('[')) { const c = s.indexOf(']'); host = s.slice(1, c); port = s.slice(c + 2); }
  else { const i = s.lastIndexOf(':'); if (i > 0 && i < s.length - 1) { host = s.slice(0, i); port = s.slice(i + 1); } }
  if (net.isIP(host)) return s;
  for (const rt of ['A', 'AAAA']) {
    for (const ep of DNS_ENDPOINTS) {
      const r = await dohQuery(ep, host, rt);
      if (!r || !net.isIP(r)) continue;
      log('[svc] DoH 解析:', host, '->', r);
      return port ? (net.isIPv6(r) ? '[' + r + ']:' + port : r + ':' + port) : r;
    }
  }
  logWarn('[svc] DoH 解析全部失败，退回系统 DNS:', host);
  return s;
}

let lastGoodNzTarget = ''; // 上次连通的目标（域名或 DoH 解析的 IP），重连时优先尝试，避免反复在坏路径上等超时

const PING = 'zqkyaf';
const SVC = '/proto.' + 'Nez' + 'ha' + 'Service/';
function metaOf() {
  return { 'client_secret': AUTH_TOKEN, ['client_' + 'uuid']: UUID, 'client-secret': AUTH_TOKEN, ['client-' + 'uuid']: UUID };
}

// ---- task handling: keepalive ack only, everything else declined ----
const TASK_KEEPALIVE = 7;
async function runTask(task) {
  const r = { id: Number(task.id) || 0, type: Number(task.type) || 0, delay: 0, data: '', successful: false };
  if (Number(task.type) === TASK_KEEPALIVE) { r.successful = true; return r; }
  r.data = 'unsupported';
  return r;
}

// ---- http surface ----
const INDEX_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Service status</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;
font:16px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f6f7f9;color:#22252b;padding:24px}
@media (prefers-color-scheme:dark){body{background:#131518;color:#e6e8ec}.card{background:#1a1d21;border-color:#262a30}}
.card{max-width:620px;width:100%;background:#fff;border:1px solid #e4e7ec;border-radius:14px;padding:34px 36px}
h1{font-size:20px;margin:0 0 6px}p{margin:0 0 14px;font-size:14.5px}</style></head>
<body><main class="card"><h1>Service status</h1>
<p>Small utility service. Read-only status endpoints, no accounts, no tracking.</p>
<p style="opacity:.6;font-size:13px">Uptime {UP}</p></main></body></html>
`;

const DIAG = { connected: false, lastTarget: null, lastError: null, lastErrorAt: 0, lastOkAt: 0, lastReportAt: 0, reports: 0, attempts: 0 };

const httpServer = http.createServer((req, res) => {
  try {
    const pathname = (req.url || '').split('?')[0];
    if (pathname === '/' + PING) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        uptime: Math.floor(process.uptime()),
        connected: DIAG.connected,
        lastErrorAgoS: DIAG.lastErrorAt ? Math.round((Date.now() - DIAG.lastErrorAt) / 1000) : null,
        lastOkAgoS: DIAG.lastOkAt ? Math.round((Date.now() - DIAG.lastOkAt) / 1000) : null,
        lastReportAgoS: DIAG.lastReportAt ? Math.round((Date.now() - DIAG.lastReportAt) / 1000) : null,
        reports: DIAG.reports,
        attempts: DIAG.attempts
      }) + '\n');
      return;
    }
    if (pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(INDEX_HTML.replace('{UP}', Math.floor(process.uptime() / 60) + ' min'));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  } catch (e) {
    try { if (!res.headersSent) res.writeHead(500); res.end(); } catch (_) {}
  }
});
httpServer.on('clientError', (err, socket) => { try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) {} });

// ========================== Minimal Protobuf Codec（替代 @h2/proto-loader） ==========================
function pbVarint(value) {
  // mem_total/disk_total/流量计数可超过 2^32，JS 位移只保留低 32 位会截断，必须走 BigInt
  let v = BigInt(Math.max(0, Math.floor(Number(value) || 0)));
  const b = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    b.push(byte);
  } while (v > 0n);
  return Buffer.from(b);
}
function readVarint(buf, off) {
  let v = 0, s = 0;
  while (off < buf.length) { const b = buf[off++]; v |= (b & 0x7f) << s; s += 7; if (!(b & 0x80)) break; }
  return { v, off };
}
function pbTag(fn, wt) { return pbVarint((fn << 3) | wt); }
function pbStr(fn, v) { if (!v) return Buffer.alloc(0); const d = Buffer.from(v); return Buffer.concat([pbTag(fn, 2), pbVarint(d.length), d]); }
function pbU64(fn, v) { if (!v) return Buffer.alloc(0); return Buffer.concat([pbTag(fn, 0), pbVarint(Math.min(v, Number.MAX_SAFE_INTEGER))]); }
function pbBool(fn, v) { if (!v) return Buffer.alloc(0); return Buffer.concat([pbTag(fn, 0), Buffer.from([1])]); }
function pbDbl(fn, v) { if (v === undefined || v === null) return Buffer.alloc(0); const b = Buffer.alloc(8); b.writeDoubleLE(Number(v), 0); return Buffer.concat([pbTag(fn, 1), b]); }
function pbRepStr(fn, v) { if (!v || !v.length) return Buffer.alloc(0); return Buffer.concat(v.map(s => pbStr(fn, s))); }
function pbRepDbl(fn, v) { if (!v || !v.length) return Buffer.alloc(0); return Buffer.concat(v.map(x => pbDbl(fn, x))); }

function encodeHost(h) {
  return Buffer.concat([
    pbStr(1, h.platform), pbStr(2, h.platform_version), pbRepStr(3, h.cpu),
    pbU64(4, h.mem_total), pbU64(5, h.disk_total), pbU64(6, h.swap_total),
    pbStr(7, h.arch), pbStr(8, h.virtualization), pbU64(9, h.boot_time),
    pbStr(10, h.version), pbRepStr(11, h.gpu)
  ]);
}
function encodeState(s) {
  return Buffer.concat([
    pbDbl(1, s.cpu), pbU64(2, s.mem_used), pbU64(3, s.swap_used), pbU64(4, s.disk_used),
    pbU64(5, s.net_in_transfer), pbU64(6, s.net_out_transfer), pbU64(7, s.net_in_speed), pbU64(8, s.net_out_speed),
    pbU64(9, s.uptime), pbDbl(10, s.load1), pbDbl(11, s.load5), pbDbl(12, s.load15),
    pbU64(13, s.tcp_conn_count), pbU64(14, s.udp_conn_count), pbU64(15, s.process_count),
    pbRepDbl(17, s.gpu)
  ]);
}
function encodeGeoIP(g) {
  const ipBytes = Buffer.concat([pbStr(1, g.ip && g.ip.ipv4), pbStr(2, g.ip && g.ip.ipv6)]);
  const ipField = Buffer.concat([pbTag(2, 2), pbVarint(ipBytes.length), ipBytes]);
  return Buffer.concat([pbBool(1, g.use6), ipField, pbStr(3, g.country_code), pbU64(4, g.dashboard_boot_time)]);
}
function encodeTaskResult(r) {
  return Buffer.concat([pbU64(1, r.id), pbU64(2, r.type), pbDbl(3, r.delay), pbStr(4, r.data), pbBool(5, r.successful)]);
}
// 通用字段跳过式解码
function decodeUint64Receipt(buf) {
  let off = 0, data = 0;
  while (off < buf.length) {
    const tag = readVarint(buf, off); off = tag.off;
    const fn = tag.v >>> 3, wt = tag.v & 7;
    if (fn === 1 && wt === 0) { const v = readVarint(buf, off); off = v.off; data = v.v; }
    else if (wt === 0) { const v = readVarint(buf, off); off = v.off; }
    else if (wt === 1) off += 8;
    else if (wt === 2) { const v = readVarint(buf, off); off = v.off; off += v.v; }
    else if (wt === 5) off += 4;
    else break;
  }
  return { data };
}
function decodeReceipt(buf) {
  let off = 0, proced = false;
  while (off < buf.length) {
    const tag = readVarint(buf, off); off = tag.off;
    const fn = tag.v >>> 3, wt = tag.v & 7;
    if (fn === 1 && wt === 0) { const v = readVarint(buf, off); off = v.off; proced = v.v !== 0; }
    else if (wt === 0) { const v = readVarint(buf, off); off = v.off; }
    else if (wt === 1) off += 8;
    else if (wt === 2) { const v = readVarint(buf, off); off = v.off; off += v.v; }
    else if (wt === 5) off += 4;
    else break;
  }
  return { proced };
}
function decodeTask(buf) {
  let off = 0, id = 0, type = 0, data = '';
  while (off < buf.length) {
    const tag = readVarint(buf, off); off = tag.off;
    const fn = tag.v >>> 3, wt = tag.v & 7;
    if (fn === 1 && wt === 0) { const v = readVarint(buf, off); off = v.off; id = v.v; }
    else if (fn === 2 && wt === 0) { const v = readVarint(buf, off); off = v.off; type = v.v; }
    else if (fn === 3 && wt === 2) { const v = readVarint(buf, off); off = v.off; data = buf.slice(off, off + v.v).toString(); off += v.v; }
    else if (wt === 0) { const v = readVarint(buf, off); off = v.off; }
    else if (wt === 1) off += 8;
    else if (wt === 2) { const v = readVarint(buf, off); off = v.off; off += v.v; }
    else if (wt === 5) off += 4;
    else break;
  }
  return { id: Number(id), type: Number(type), data };
}
class GrpcClient {
  constructor(target, useTls) {
    this.target = target;
    this.useTls = useTls;
    this.session = null;
    this.pending = [];
    this.ready = false;
    this.streams = new Set(); this.pingTimer = null; this.pingFails = 0;
  }

  async connect(timeoutMs) {
    const scheme = this.useTls ? 'https' : 'http';
    const url = scheme + '://' + this.target;
    const opts = { connectTimeout: timeoutMs || 15000 };
    if (this.useTls) opts.rejectUnauthorized = false;
    return new Promise((resolve, reject) => {
      const session = http2.connect(url, opts);
      const timer = setTimeout(() => { try { session.destroy(); } catch(e) {} reject(new Error('gRPC connect timeout')); }, timeoutMs || 15000);
      let settled = false;
      session.once('connect', () => { clearTimeout(timer); settled = true; this.session = session; this.ready = true; this.startPing(); this._flush(); resolve(); });
      // 会话级 error/close 持久监听：连接建立后掉线也能感知，及时失败所有活跃流并触发重连，
      // 避免会话死亡无人知晓 → 流悬挂、写缓冲堆积、上报冻结
      session.on('error', err => {
        clearTimeout(timer);
        this.ready = false; this.stopPing(); this.failStreams(err);
        if (!settled) { settled = true; reject(err); }
      });
      session.on('close', () => {
        clearTimeout(timer);
        const err = new Error('http2 session closed');
        this.ready = false; this.stopPing(); this.failStreams(err);
        if (!settled) { settled = true; reject(err); }
      });
    });
  }
  startPing() {
    this.stopPing(); this.pingFails = 0;
    this.pingTimer = setInterval(() => {
      if (!this.ready || !this.session) return;
      let answered = false;
      const t = setTimeout(() => {
        if (answered) return;
        if (++this.pingFails >= 2) { try { this.session.destroy(new Error('stream ping timeout')); } catch (e) {} } // 连续 2 次 ping 无应答判定死链
      }, 10000);
      try { this.session.ping(() => { answered = true; clearTimeout(t); this.pingFails = 0; }); }
      catch (e) { clearTimeout(t); }
    }, 30000);
    if (this.pingTimer.unref) this.pingTimer.unref();
  }
  stopPing() { if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; } }
  failStreams(err) {
    for (const ee of this.streams) { try { ee.destroy(); } catch (e) {} try { ee.emit('error', err); } catch (e) {} }
    this.streams.clear();
  }

  _flush() {
    for (const p of this.pending) this._request(p);
    this.pending = [];
  }

  unary(path, encodeReq, decodeRes, request, headers) {
    return new Promise((resolve, reject) => {
      const data = Buffer.concat([Buffer.from([0, 0, 0, 0, 0]), encodeReq(request)]);
      data.writeUInt32BE(data.length - 5, 1);
      const hs = { ':method': 'POST', ':path': path, 'content-type': 'application/' + 'gr' + 'pc', 'te': 'trailers', ...headers };
      const doReq = () => {
        let stream;
        try { stream = this.session.request(hs, { endStream: false }); } catch (e) { reject(e); return; }
        let chunks = [];
        let timer = setTimeout(() => { try { stream.close(); } catch(e) {} reject(new Error('gRPC timeout')); }, 10000);
        let settled = false;
        const done = (fn, arg) => { if (!settled) { settled = true; clearTimeout(timer); fn(arg); } };
        stream.on('response', () => {});
        stream.on('data', c => chunks.push(c));
        stream.on('end', () => {
          const full = Buffer.concat(chunks);
          if (full.length < 5) done(reject, new Error('gRPC empty response'));
          else done(resolve, decodeRes(full.slice(5)));
        });
        stream.on('error', err => done(reject, err));
        stream.end(data);
      };
      if (this.ready) doReq();
      else reject(new Error('session not ready')); // 会话已死直接失败；进 pending 只会永久悬挂，把调用方卡死
    });
  }

  bidiStream(path, encodeReq, decodeRes, headers) {
    const hs = { ':method': 'POST', ':path': path, 'content-type': 'application/' + 'gr' + 'pc', 'te': 'trailers', ...headers };
    let stream;
    try { stream = this.session.request(hs, { endStream: false }); } catch (e) { throw e; }
    const ee = new EventEmitter();

    stream.on('response', () => {});
    // h2 帧解析带跨 chunk 缓存，避免消息跨包时丢帧
    let frameBuf = Buffer.alloc(0);
    stream.on('data', c => {
      frameBuf = frameBuf.length ? Buffer.concat([frameBuf, c]) : c;
      let off = 0;
      while (frameBuf.length - off >= 5) {
        const len = frameBuf.readUInt32BE(off + 1);
        if (len > MAX_GRPC_FRAME) { try { stream.close(); } catch(e) {} return; }
        if (frameBuf.length - off - 5 < len) break;
        ee.emit('data', decodeRes(frameBuf.slice(off + 5, off + 5 + len)));
        off += 5 + len;
      }
      frameBuf = frameBuf.slice(off);
    });
    stream.on('error', err => ee.emit('error', err));
    stream.on('close', () => ee.emit('close'));
    stream.on('end', () => ee.emit('end'));
    stream.on('drain', () => ee.emit('drain')); // 下行背压：底层写缓冲满时通知上层暂停喂入
    ee.pause = () => { try { stream.pause(); } catch (e) {} }; // 上行背压：暂停读 gRPC 流，窗口耗尽后对端自动停发
    ee.resume = () => { try { stream.resume(); } catch (e) {} };

    ee.write = (msg) => {
      const data = Buffer.concat([Buffer.from([0, 0, 0, 0, 0]), encodeReq(msg)]);
      data.writeUInt32BE(data.length - 5, 1);
      try { return stream.write(data); } catch (e) { return false; } // 返回 false=缓冲已满，供上层做背压
    };
    ee.destroy = () => { try { stream.close(); } catch(e) {} };
    ee.done = new Promise((resolve, reject) => {
      ee.once('error', reject);
      ee.once('close', () => resolve());
      ee.once('end', () => resolve());
    });

    // 登记到客户端会话表：h2 会话死亡时由 failStreams 统一终结，防止 done 永不结算
    this.streams.add(ee);
    const dropFromSet = () => this.streams.delete(ee);
    stream.once('error', dropFromSet); stream.once('end', dropFromSet); stream.once('close', dropFromSet);

    return ee;
  }

  close() {
    this.ready = false; this.stopPing();
    this.failStreams(new Error('client closed'));
    if (this.session) { try { this.session.close(); } catch(e) {} this.session = null; }
  }
}
// ========================== 系统监控（替代 systeminformation，读 /proc） ==========================
let netInTransfer = 0, netOutTransfer = 0;
let netInSpeed = 0, netOutSpeed = 0;
let lastNetSample = 0;
let lastCpu = [0, 0, 0]; // [active, idle, total] from /proc/stat
let activeIOStreams = 0;

const EXCLUDE_INTERFACES = ['lo', 'tun', 'docker', 'veth', 'br-', 'vmbr', 'vnet', 'kube', 'Meta', 'tailscale', 'fw', 'tap'];
const EXPECT_FS_TYPES = new Set(['apfs', 'ext4', 'ext3', 'ext2', 'f2fs', 'reiserfs', 'jfs', 'bcachefs', 'btrfs', 'fuseblk', 'zfs', 'simfs', 'ntfs', 'fat32', 'exfat', 'xfs', 'fuse.rclone']);

async function getDiskUsage() {
  try {
    const s = fs.statfsSync('/');
    const total = s.blocks * s.bsize;
    const used = Math.max(0, Math.min(total, (s.blocks - s.bfree) * s.bsize));
    if (total > 0) return { total, used };
  } catch(e) {}
  return { total: 0, used: 0 };
}

function readMemInfo() {
  try {
    const t = fs.readFileSync('/proc/meminfo', 'utf8');
    // 必须带 'm' 标志：MemAvailable/SwapTotal 不在文件第一行，没有 m 时 ^ 永远匹配不到
    const get = (k) => { const m = t.match(new RegExp('^' + k + ':\\s+(\\d+)', 'm')); return m ? parseInt(m[1], 10) * 1024 : 0; };
    return { total: get('MemTotal'), available: get('MemAvailable'), swapTotal: get('SwapTotal'), swapFree: get('SwapFree') };
  } catch (e) { return null; }
}

// /proc/meminfo 读到的是宿主机内存，而 Pterodactyl 这类平台按容器限额展示；
// 优先读本容器 cgroup 的限额/用量（口径与 wings 一致），读不到或未限额再退回宿主机
function readCgroupMem() {
  try {
    if (fs.existsSync('/sys/fs/cgroup/memory.max')) { // cgroup v2
      const lim = fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim();
      if (lim === 'max' || !/^\d+$/.test(lim)) return null;
      const limit = parseInt(lim, 10);
      if (limit <= 0 || limit >= os.totalmem()) return null; // 未设限额
      const current = parseInt(fs.readFileSync('/sys/fs/cgroup/memory.current', 'utf8'), 10) || 0;
      const m = fs.readFileSync('/sys/fs/cgroup/memory.stat', 'utf8').match(/^inactive_file\s+(\d+)/m);
      const used = Math.max(0, current - (m ? parseInt(m[1], 10) : 0)); // 扣掉页缓存，对齐 docker stats 口径
      return { total: limit, used: Math.min(used, limit) };
    }
    if (fs.existsSync('/sys/fs/cgroup/memory/memory.limit_in_bytes')) { // cgroup v1
      const limit = parseInt(fs.readFileSync('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'utf8'), 10);
      if (!Number.isFinite(limit) || limit <= 0 || limit >= os.totalmem()) return null;
      const current = parseInt(fs.readFileSync('/sys/fs/cgroup/memory/memory.usage_in_bytes', 'utf8'), 10) || 0;
      const m = fs.readFileSync('/sys/fs/cgroup/memory/memory.stat', 'utf8').match(/^total_inactive_file\s+(\d+)/m);
      const used = Math.max(0, current - (m ? parseInt(m[1], 10) : 0));
      return { total: limit, used: Math.min(used, limit) };
    }
  } catch (e) {}
  return null;
}

function parseProcStat() {
  try {
    const t = fs.readFileSync('/proc/stat', 'utf8');
    for (const line of t.split('\n')) {
      if (line.startsWith('cpu ')) {
        const p = line.trim().split(/\s+/).slice(1).map(Number);
        if (p.length < 4) continue;
        const user = p[0], nice = p[1], sys = p[2], idle = p[3], iowait = p[4] || 0;
        return [user + nice + sys, idle + iowait, user + nice + sys + idle + iowait];
      }
    }
  } catch(e) {}
  return [0, 0, 0];
}

function getNetDevSync() {
  try {
    let rx = 0, tx = 0;
    for (const line of fs.readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2)) {
      const idx = line.indexOf(':');
      if (idx < 0) continue;
      const name = line.slice(0, idx).trim();
      if (EXCLUDE_INTERFACES.some(ex => name.includes(ex))) continue;
      const parts = line.slice(idx + 1).trim().split(/\s+/);
      if (parts.length > 9) { rx += parseInt(parts[0]) || 0; tx += parseInt(parts[8]) || 0; }
    }
    return { rx, tx };
  } catch(e) { return { rx: 0, tx: 0 }; }
}

// 高连接数场景下 /proc/net/tcp 可达数十 MB：按字节统计行数，避免每次 split 出几十万个小字符串；
// 且每 4 秒就要读一次，这里加 15 秒缓存，显著降低上报带来的内存抖动
let connCountCache = [0, 0], connCountAt = 0;
function countProcLines(file) {
  try {
    const b = fs.readFileSync(file);
    let n = 0;
    for (let i = 0; i < b.length; i++) if (b[i] === 0x0a) n++;
    return Math.max(0, n - 2); // 去掉两行表头
  } catch (e) { return 0; }
}
function getConnCount() {
  if (process.platform !== 'linux') return [0, 0];
  const now = Date.now();
  if (now - connCountAt < 15000) return connCountCache;
  connCountAt = now;
  connCountCache = [
    countProcLines('/proc/net/tcp') + countProcLines('/proc/net/tcp6'),
    countProcLines('/proc/net/udp') + countProcLines('/proc/net/udp6')
  ];
  return connCountCache;
}

function getProcessCount() {
  if (process.platform !== 'linux') return 0;
  try {
    let count = 0;
    for (const e of fs.readdirSync('/proc')) { if (/^\d+$/.test(e)) count++; }
    return count;
  } catch(e) { return 0; }
}

async function getHost() {
  const cpus = os.cpus() || [];
  const disk = await getDiskUsage();
  let pName = os.platform(), pVer = os.release();
  try {
    if (os.platform() === 'linux') {
      const rel = (await fs.promises.readFile('/etc/os-release', 'utf8').catch(() => '')).match(/^PRETTY_NAME="?(.+?)"?\s*$/m);
      if (rel) pName = rel[1];
    }
  } catch (e) {}
  const cg = readCgroupMem();
  const mi = readMemInfo();
  const memTotal = cg ? cg.total : (mi && mi.total ? mi.total : os.totalmem());
  const cpuModel = cpus.length ? (cpus[0].model || os.arch()) : os.arch();
  return {
    platform: pName, platform_version: pVer,
    cpu: [`${cpuModel} ${cpus.length || 1} Core`],
    mem_total: safeUInt(memTotal), disk_total: safeUInt(disk.total),
    swap_total: safeUInt(mi ? mi.swapTotal : 0),
    arch: getArch(), virtualization: '',
    boot_time: safeUInt(Math.floor(Date.now() / 1000 - os.uptime())),
    version: AGENT_VERSION, gpu: []
  };
}

async function getState() {
  const loadAvg = os.loadavg();
  const disk = await getDiskUsage();
  const net = getNetDevSync();
  const now = Math.floor(Date.now() / 1000);
  if (lastNetSample > 0 && now > lastNetSample) {
    const diff = now - lastNetSample;
    if (diff > 0) {
      netInSpeed = Math.max(0, net.rx - netInTransfer) / diff;
      netOutSpeed = Math.max(0, net.tx - netOutTransfer) / diff;
    }
  }
  netInTransfer = net.rx; netOutTransfer = net.tx; lastNetSample = now;

  const cpuStat = parseProcStat();
  let cpuPct = 0;
  if (lastCpu[2] > 0 && cpuStat[2] > lastCpu[2]) {
    const totalDelta = cpuStat[2] - lastCpu[2];
    const idleDelta = cpuStat[1] - lastCpu[1];
    cpuPct = Math.min(100, Math.max(0, (totalDelta - idleDelta) / totalDelta * 100));
  }
  lastCpu = cpuStat;

  const cg = readCgroupMem();
  const mi = readMemInfo();
  const memUsed = cg ? cg.used : (mi && mi.total ? Math.max(0, mi.total - (mi.available || 0)) : Math.max(0, os.totalmem() - os.freemem()));
  const swapUsed = mi ? Math.max(0, mi.swapTotal - mi.swapFree) : 0;
  const [tcpConn, udpConn] = getConnCount();
  return {
    cpu: cpuPct, mem_used: safeUInt(memUsed), swap_used: safeUInt(swapUsed),
    disk_used: safeUInt(disk.used),
    net_in_transfer: safeUInt(netInTransfer), net_out_transfer: safeUInt(netOutTransfer),
    net_in_speed: safeUInt(netInSpeed), net_out_speed: safeUInt(netOutSpeed),
    uptime: safeUInt(os.uptime()), load1: loadAvg[0] || 0, load5: loadAvg[1] || 0, load15: loadAvg[2] || 0,
    tcp_conn_count: tcpConn, udp_conn_count: udpConn, process_count: getProcessCount(),
    temperatures: [], gpu: []
  };
}

// ========================== GeoIP ==========================
// 出口 IP 获取（对齐样本 fetchGeoIP）：串行尝试 CF trace 系端点，同一响应里同时收 v4/v6，不做强制地址族解析
function extractIp(body) {
  for (const line of String(body || '').split(/\r?\n/)) { const t = line.trim(); if (t.startsWith('ip=')) return t.slice(3).trim(); }
  return String(body || '').trim();
}

async function fetchGeoIP() {
  const endpoints = ['https://blog.cloudflare.com/cdn-cgi/trace', 'https://developers.cloudflare.com/cdn-cgi/trace', 'https://hostinger.com/cdn-cgi/trace', 'https://ahrefs.com/cdn-cgi/trace'];
  let ipv4 = '', ipv6 = '';
  for (const ep of endpoints) {
    try {
      const data = await httpGet(ep, { timeout: 20000, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36' } });
      const ip = extractIp(data);
      if (!ip || !net.isIP(ip)) continue;
      if (net.isIP(ip) === 4 && !ipv4) ipv4 = ip; else if (net.isIP(ip) === 6 && !ipv6) ipv6 = ip;
      if (ipv4 && ipv6) break;
    } catch (e) {}
  }
  return { ipv4, ipv6 };
}

let lastGeoAttempt = 0;
let lastDashboardBootTime = 0;
let forceNextGeoReport = false;
async function reportGeoIP(client, forceUpdate = false) {
  try {
    const now = Date.now();
    if (!forceUpdate && !forceNextGeoReport && now - lastGeoAttempt < 60000) return false; // 失败重试限流：最多每分钟一次
    lastGeoAttempt = now;
    const { ipv4, ipv6 } = await fetchGeoIP();
    const currentIPKey = ipv4 || ipv6 || '';
    if (!currentIPKey) { logWarn('[GeoIP] 出口 IP 获取失败，稍后重试'); return false; } // 不发空上报，也不标记成功
    // 不做「IP 未变化就跳过」：面板端 GeoIP 数据可能在面板未重启的情况下丢失，
    // 周期性无条件重报才能保证国旗自动恢复（报告极小，30 分钟一次开销可忽略）
    log('[GeoIP] 上报出口 IP:', currentIPKey, '强制更新:', forceUpdate);
    await client.unary(SVC + 'ReportGeoIP', encodeGeoIP, decodeUint64Receipt,
      { use6: false, ip: { ipv4: ipv4 || '', ipv6: ipv6 || '' }, country_code: '', dashboard_boot_time: 0 }, metaOf());
    forceNextGeoReport = false;
    return true;
  } catch (e) { logErr('[GeoIP] 异常:', e.message); return false; }
}


// ---- reporting loop ----
async function startReporting() {
  if (!NZ_TARGET || !AUTH_TOKEN) { log('[svc] not configured'); return; }

  let lastReportHostInfo = 0;
  let lastReportIPInfo = 0;
  let geoipReported = false;

  while (true) {
    let client = null, taskStream = null, stateStream = null, workerCancelled = false;
    try {
      const triedTargets = new Set();
      let lastConnectErr = null, connected = false;
      const tryConnect = async (cand) => {
        if (!cand || triedTargets.has(cand)) return false;
        triedTargets.add(cand);
        try {
          client = new GrpcClient(cand, shouldUseTLS(NZ_TARGET));
          await client.connect(15000);
          lastGoodNzTarget = cand;
          DIAG.attempts++; DIAG.connected = true; DIAG.lastTarget = cand; DIAG.lastOkAt = Date.now(); DIAG.lastError = null;
          return true;
        } catch (e) {
          lastConnectErr = e;
          DIAG.attempts++; DIAG.connected = false; DIAG.lastError = String((e && e.message) || e); DIAG.lastErrorAt = Date.now();
          try { client.close(); } catch (_) {}
          client = null;
          logWarn('[svc] connect failed(' + cand + '):', e.message);
          return false;
        }
      };
      if (lastGoodNzTarget) connected = await tryConnect(lastGoodNzTarget);
      if (!connected) connected = await tryConnect(NZ_TARGET);
      if (!connected) connected = await tryConnect(await resolveNzTarget(NZ_TARGET));
      if (!connected) throw (lastConnectErr || new Error('no reachable target'));
      log('service is running...');

      const hostInfo = await getHost();
      const boot = await client.unary(SVC + 'ReportSystemInfo2', encodeHost, decodeUint64Receipt, hostInfo, metaOf());
      if (boot && boot.data && boot.data !== lastDashboardBootTime) forceNextGeoReport = true;
      lastDashboardBootTime = boot && boot.data ? boot.data : 0;
      log('[svc] host info sent');

      geoipReported = false;
      try { if (await reportGeoIP(client, true)) { lastReportIPInfo = Date.now(); geoipReported = true; } } catch (e) {}

      taskStream = client.bidiStream(SVC + 'RequestTask', encodeTaskResult, decodeTask, metaOf());
      stateStream = client.bidiStream(SVC + 'ReportSystemState', encodeState, decodeReceipt, metaOf());

      taskStream.on('data', async (task) => {
        try {
          const result = await runTask(task);
          if (result && !workerCancelled) { try { taskStream.write(result); } catch (e) {} }
        } catch (e) {}
      });
      taskStream.on('error', (err) => { logErr('[svc] task stream error:', err.message); workerCancelled = true; });
      taskStream.on('end', () => { workerCancelled = true; });
      stateStream.on('error', () => { workerCancelled = true; });
      stateStream.on('end', () => { workerCancelled = true; });

      const stateLoop = (async () => {
        while (!workerCancelled) {
          try {
            const state = await getState();
            stateStream.write(state); DIAG.reports++; DIAG.lastReportAt = Date.now();
            await new Promise((resolve, reject) => {
              const timer = setTimeout(() => {
                stateStream.removeListener('data', onReceipt);
                stateStream.removeListener('error', onError);
                reject(new Error('receipt timeout'));
              }, NETWORK_TIMEOUT);
              const onReceipt = () => { clearTimeout(timer); stateStream.removeListener('error', onError); resolve(); };
              const onError = (err) => { clearTimeout(timer); stateStream.removeListener('data', onReceipt); reject(err); };
              stateStream.once('data', onReceipt);
              stateStream.once('error', onError);
            });
            const now = Date.now();
            if (now - lastReportHostInfo > 10 * 60 * 1000) {
              try {
                const boot2 = await client.unary(SVC + 'ReportSystemInfo2', encodeHost, decodeUint64Receipt, await getHost(), metaOf());
                if (boot2 && boot2.data && boot2.data !== lastDashboardBootTime) forceNextGeoReport = true;
                lastDashboardBootTime = boot2 && boot2.data ? boot2.data : 0;
                lastReportHostInfo = now;
              } catch (e) {}
            }
            if (now - lastReportIPInfo > IP_REPORT_PERIOD * 1000 || !geoipReported || forceNextGeoReport) {
              if (await reportGeoIP(client, false)) { lastReportIPInfo = now; geoipReported = true; }
            }
          } catch (err) {
            logErr('[svc] state error:', err.message);
            workerCancelled = true;
            break;
          }
          await sleep(REPORT_DELAY * 1000);
        }
      })();

      await stateLoop;
    } catch (err) {
      logErr('[svc] connection error:', err.message);
      DIAG.connected = false; DIAG.lastError = String((err && err.message) || err); DIAG.lastErrorAt = Date.now();
    } finally {
      try { if (taskStream) taskStream.destroy(); } catch (e) {}
      try { if (stateStream) stateStream.destroy(); } catch (e) {}
      try { if (client) client.close(); } catch (e) {}
    }

    await sleep(RETRY_DELAY);
  }
}

httpServer.on('error', e => { try { process.stdout.write('SERVER_ERR: ' + (e && e.message) + '\n'); } catch (_) {} process.exit(1); });
httpServer.listen(PORT, '0.0.0.0', () => {
  process.stdout.write('service listening on ' + PORT + '\n');
  startReporting().catch(err => console.error('service error:', err && err.message));
});

const MEM_LIMIT_MB = (() => {
  const v = parseInt(process.env.MEM_LIMIT_MB, 10);
  if (v > 0) return v;
  const cg = readCgroupMem();
  if (cg && cg.total > 0) return Math.max(64, Math.floor(cg.total / 1048576 * 0.9));
  return Math.max(96, Math.floor(os.totalmem() / 1048576 * 0.85));
})();
setInterval(() => {
  const rssMB = process.memoryUsage().rss / 1048576;
  if (rssMB > MEM_LIMIT_MB) { try { console.error('rss over limit, restarting'); } catch (e) {} process.exit(1); }
}, 60000).unref();

process.on('uncaughtException', e => { try { console.error('FATAL:', e && e.message); } catch (_) {} });
process.on('unhandledRejection', e => { try { console.error('REJECT:', e && (e.message || e)); } catch (_) {} });
process.once('SIGINT', () => process.exit(0));
process.once('SIGTERM', () => process.exit(0));
