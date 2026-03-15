'use strict';

const { Adapter } = require('@iobroker/adapter-core');
const http        = require('http');
const net         = require('net');
const url         = require('url');
const fs          = require('fs');
const os          = require('os');
const path        = require('path');
const { exec }    = require('child_process');

// ─── TR-064 SOAP ─────────────────────────────────────────────────────────────

function soapRequest(host, port, service, action, body, user, pass) {
    return new Promise((resolve, reject) => {
        const xml =
            '<?xml version="1.0" encoding="utf-8"?>' +
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"' +
            ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
            '<s:Body>' + body + '</s:Body></s:Envelope>';

        const auth = 'Basic ' + Buffer.from(user + ':' + pass).toString('base64');
        const opts = {
            hostname: host, port: port || 49000, path: service, method: 'POST',
            headers: {
                'Content-Type':   'text/xml; charset=utf-8',
                'SOAPAction':     '"' + action + '"',
                'Content-Length': Buffer.byteLength(xml),
                'Authorization':  auth
            }
        };
        const req = http.request(opts, res => {
            let data = '';
            res.on('data', d => data += d);
            res.on('end',  () => resolve(data));
        });
        req.on('error', reject);
        req.setTimeout(8000, () => { req.destroy(); reject(new Error('TR-064 Timeout')); });
        req.write(xml);
        req.end();
    });
}

function parseXml(xml, tag) {
    const m = xml.match(new RegExp('<' + tag + '>([\\s\\S]*?)<\\/' + tag + '>'));
    return m ? m[1].trim() : null;
}

// ─── WireGuard Config Sanitizer ───────────────────────────────────────────────
// Verhindert DNS-Manipulation und Full-Tunnel durch wg-quick

function sanitizeWgConfig(raw) {
    const warnings = [];
    let cfg = raw;

    if (/^DNS\s*=/mi.test(cfg)) {
        cfg = cfg.replace(/^DNS\s*=.+\n?/gim, '');
        warnings.push('DNS-Zeilen entfernt \u2014 verhindert systemweite DNS-\u00c4nderung durch wg-quick.');
    }
    if (/0\.0\.0\.0\/0/.test(cfg)) {
        cfg = cfg.replace(/,\s*0\.0\.0\.0\/0/g, '').replace(/0\.0\.0\.0\/0\s*,?\s*/g, '');
        warnings.push('0.0.0.0/0 aus AllowedIPs entfernt \u2014 Full-Tunnel w\u00fcrde lokalen Netzwerkzugriff anderer Adapter blockieren.');
    }
    if (/::\/0/.test(cfg)) {
        cfg = cfg.replace(/,\s*::\/0/g, '').replace(/::\/0\s*,?\s*/g, '');
        warnings.push('::/0 aus AllowedIPs entfernt (IPv6 Full-Tunnel).');
    }
    return { cfg, warnings };
}

// ─── WireGuard System-Calls ───────────────────────────────────────────────────

function wgStatus(iface) {
    return new Promise(resolve => {
        exec('wg show ' + iface, (err, stdout) => {
            if (err) return resolve({ connected: false, peers: [] });
            const peers = [];
            for (const block of stdout.split(/\n\n/)) {
                if (!block.startsWith('peer:')) continue;
                peers.push({
                    pubkey:    (block.match(/^peer: (.+)/m)  || [])[1] || '',
                    endpoint:  (block.match(/endpoint: (.+)/m) || [])[1] || '',
                    handshake: (block.match(/latest handshake: (.+)/m) || [])[1] || 'nie',
                    rx: parseInt((block.match(/transfer: ([\d]+) B received/m) || [])[1] || '0'),
                    tx: parseInt((block.match(/transfer: [\d]+ B received, ([\d]+) B sent/m) || [])[1] || '0')
                });
            }
            resolve({ connected: true, peers });
        });
    });
}

function wgUp(cfgPath) {
    return new Promise((resolve, reject) => {
        exec('wg-quick up ' + cfgPath + ' 2>&1', (err, out) => err ? reject(new Error(out || err.message)) : resolve(out));
    });
}

function wgDown(cfgPath) {
    return new Promise((resolve) => {
        // Timeout: wg-quick down darf max 4s blockieren
        const timer = setTimeout(() => resolve('timeout'), 4000);
        exec('wg-quick down ' + cfgPath + ' 2>&1', (_err, out) => {
            clearTimeout(timer);
            resolve(out || '');
        });
    });
}

// ─── TCP Tunnel Manager ───────────────────────────────────────────────────────
// \u00d6ffnet lokale Ports auf 127.0.0.1 und leitet Verbindungen transparent
// durch den WireGuard-Tunnel weiter. Andere Adapter nutzen 127.0.0.1:localPort.

class TunnelManager {
    constructor(logFn) {
        this._log     = logFn;
        this._servers = new Map();  // id \u2192 { server, cfg }
        this._stats   = new Map();  // id \u2192 { active, total, rx, tx, error }
    }

    start(t) {
        const id = t.id || t.name;
        if (this._servers.has(id) || !t.enabled) return;

        const stats = { active: 0, total: 0, rxBytes: 0, txBytes: 0, error: null };
        this._stats.set(id, stats);

        const server = net.createServer(local => {
            stats.active++;
            stats.total++;
            const remote = net.connect(parseInt(t.remotePort), t.remoteHost, () => {
                this._log('INFO', 'TUNNEL',
                    t.name + ': ' + local.remoteAddress + ' \u2192 ' + t.remoteHost + ':' + t.remotePort);
            });

            local.pipe(remote);
            remote.pipe(local);
            local.on('data',  d => { stats.rxBytes += d.length; });
            remote.on('data', d => { stats.txBytes += d.length; });

            const end = () => {
                stats.active = Math.max(0, stats.active - 1);
                local.destroy();
                remote.destroy();
            };
            local.on('close',  end);
            remote.on('close', end);
            local.on('error',  e => { this._log('WARN', 'TUNNEL', t.name + ' local: '  + e.message); end(); });
            remote.on('error', e => { this._log('WARN', 'TUNNEL', t.name + ' remote: ' + e.message); end(); });
        });

        server.on('error', e => {
            stats.error = e.message;
            this._log('ERROR', 'TUNNEL', t.name + ': Port ' + t.localPort + ' Fehler: ' + e.message);
        });

        server.listen(parseInt(t.localPort), '127.0.0.1', () => {
            this._log('INFO', 'TUNNEL',
                t.name + ': 127.0.0.1:' + t.localPort + ' \u2192 ' + t.remoteHost + ':' + t.remotePort);
        });

        this._servers.set(id, { server, cfg: t });
    }

    startAll(tunnels) { for (const t of (tunnels || [])) this.start(t); }

    stop(id) {
        const e = this._servers.get(id);
        if (e) { e.server.close(); this._servers.delete(id); this._stats.delete(id); }
    }

    stopAll() { for (const id of [...this._servers.keys()]) this.stop(id); }

    statusAll(tunnelCfg) {
        return (tunnelCfg || []).map(t => {
            const id    = t.id || t.name;
            const stats = this._stats.get(id) || {};
            return {
                id, name: t.name,
                localPort: t.localPort, remoteHost: t.remoteHost, remotePort: t.remotePort,
                enabled:  t.enabled,
                running:  this._servers.has(id),
                active:   stats.active  || 0,
                total:    stats.total   || 0,
                rxBytes:  stats.rxBytes || 0,
                txBytes:  stats.txBytes || 0,
                error:    stats.error   || null
            };
        });
    }
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

class FritzWireguard extends Adapter {

    constructor(options = {}) {
        super({ ...options, name: 'fritzwireguard' });
        this._server    = null;
        this._logBuffer = [];
        this._pollTimer = null;
        this._wgCfgPath = null;
        this._cache     = { wg: {}, fritzbox: {}, devices: [] };
        this._tunnelMgr = null;
        this.on('ready',       this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload',      this.onUnload.bind(this));
    }

    // Logging
    _log(level, category, msg) {
        const e = { ts: Date.now(), level, category, msg };
        this._logBuffer.unshift(e);
        if (this._logBuffer.length > ((this.config && this.config.logBuffer) || 500)) this._logBuffer.pop();
        // this.log kann in fruehen Initialisierungsphasen noch undefined sein
        const l = this.log;
        if (!l) { console.log('[' + level + '][' + category + '] ' + msg); return; }
        if (level === 'ERROR') l.error('[' + category + '] ' + msg);
        else if (level === 'WARN') l.warn('[' + category + '] ' + msg);
        else l.debug('[' + category + '] ' + msg);
    }

    // States
    async _initStates() {
        // Parent-Channels zuerst anlegen (adapter-core v3 benoetigt das)
        for (const [chId, chName] of [
            ['info',      'Adapter-Info'],
            ['wireguard', 'WireGuard'],
            ['fritzbox',  'FritzBox'],
        ]) {
            try {
                await this.extendObjectAsync(chId, {
                    type:   'channel',
                    common: { name: chName },
                    native: {}
                });
            } catch (_e) { /* channel already exists or non-critical */ }
        }

        // States anlegen/aktualisieren
        // extendObjectAsync ist zuverlaessiger als setObjectNotExistsAsync in adapter-core v3
        for (const [id, stateType, defVal, stName, role] of [
            ['info.connection',          'boolean', false, 'Adapter verbunden',      'indicator.connected'],
            ['info.lastUpdate',          'string',  '',    'Letzte Aktualisierung',  'date'],
            ['wireguard.status',         'string',  '',    'WireGuard Status',       'text'],
            ['wireguard.handshake',      'string',  '',    'Letzter Handshake',      'date'],
            ['wireguard.rxBytes',        'number',  0,     'Empfangene Bytes',       'value'],
            ['wireguard.txBytes',        'number',  0,     'Gesendete Bytes',        'value'],
            ['fritzbox.externalIP',      'string',  '',    'Externe IP',             'text'],
            ['fritzbox.uptime',          'number',  0,     'Uptime (Sekunden)',      'value'],
            ['fritzbox.connectionType',  'string',  '',    'Verbindungstyp',         'text'],
            ['fritzbox.modelName',       'string',  '',    'FritzBox Modell',        'text'],
            ['fritzbox.firmwareVersion', 'string',  '',    'Firmware-Version',       'text'],
        ]) {
            try {
                await this.extendObjectAsync(id, {
                    type:   'state',
                    common: {
                        name:  stName,
                        type:  stateType,
                        role:  role,
                        read:  true,
                        write: false,
                        def:   defVal
                    },
                    native: {}
                });
            } catch (_e) { /* state already exists or non-critical */ }
        }
    }

    // WireGuard Config
    _writeTempConfig() {
        const { cfg, warnings } = sanitizeWgConfig(this.config.wgConfig || '');
        for (const w of warnings) this._log('WARN', 'WG', w);
        const dir  = path.join(os.tmpdir(), 'fritzwireguard');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        const file = path.join(dir, 'wg-fritzwireguard.conf');
        fs.writeFileSync(file, cfg, { mode: 0o600 });
        this._wgCfgPath = file;
        return file;
    }

    // WireGuard Connect / Disconnect
    async _connectWg() {
        try {
            this._log('INFO', 'WG', 'Starte WireGuard \u2026');
            await wgUp(this._writeTempConfig());
            this._log('INFO', 'WG', 'WireGuard verbunden.');
            return true;
        } catch (e) {
            this._log('ERROR', 'WG', 'wg-quick up: ' + e.message);
            return false;
        }
    }

    async _disconnectWg() {
        if (!this._wgCfgPath) return;
        try { await wgDown(this._wgCfgPath); this._log('INFO', 'WG', 'WireGuard getrennt.'); }
        catch (e) { this._log('WARN', 'WG', 'wg-quick down: ' + e.message); }
    }

    // FritzBox TR-064
    async _pollFritzBox() {
        const h = this.config.fritzHost || '192.168.178.1';
        const p = parseInt(this.config.fritzPort) || 49000;
        const u = this.config.fritzUser || '';
        const pw = this.config.fritzPass || '';

        const set = async (state, val) => {
            this._cache.fritzbox[state.split('.')[1]] = val;
            await this.setStateAsync('fritzbox.' + state.split('.')[1], { val, ack: true });
        };

        try {
            const r = await soapRequest(h, p,
                '/igdupnp/control/WANIPConn1',
                'urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress',
                '<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>', u, pw);
            const ip = parseXml(r, 'NewExternalIPAddress');
            if (ip) await set('fritzbox.externalIP', ip);
        } catch (e) { this._log('WARN', 'TR064', 'WAN-IP: ' + e.message); }

        try {
            const r = await soapRequest(h, p,
                '/igdupnp/control/WANIPConn1',
                'urn:schemas-upnp-org:service:WANIPConnection:1#GetStatusInfo',
                '<u:GetStatusInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>', u, pw);
            const up = parseXml(r, 'NewUptime');
            const ct = parseXml(r, 'NewConnectionType') || parseXml(r, 'NewConnectionStatus');
            if (up) await set('fritzbox.uptime', parseInt(up));
            if (ct) await set('fritzbox.connectionType', ct);
        } catch (e) { this._log('WARN', 'TR064', 'Status: ' + e.message); }

        try {
            const r = await soapRequest(h, p,
                '/tr064/upnp/control/deviceinfo',
                'urn:dslforum-org:service:DeviceInfo:1#GetInfo',
                '<u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1"/>', u, pw);
            const m = parseXml(r, 'NewModelName');
            const f = parseXml(r, 'NewSoftwareVersion');
            if (m) await set('fritzbox.modelName', m);
            if (f) await set('fritzbox.firmwareVersion', f);
        } catch (e) { this._log('WARN', 'TR064', 'DeviceInfo: ' + e.message); }

        await this._pollHosts(h, p, u, pw);
    }

    async _pollHosts(h, p, u, pw) {
        try {
            const cr = await soapRequest(h, p,
                '/tr064/upnp/control/hosts',
                'urn:dslforum-org:service:Hosts:1#GetHostNumberOfEntries',
                '<u:GetHostNumberOfEntries xmlns:u="urn:dslforum-org:service:Hosts:1"/>', u, pw);
            const count   = parseInt(parseXml(cr, 'NewHostNumberOfEntries') || '0');
            const devices = [];

            for (let i = 0; i < count; i++) {
                try {
                    const r = await soapRequest(h, p,
                        '/tr064/upnp/control/hosts',
                        'urn:dslforum-org:service:Hosts:1#GetGenericHostEntry',
                        '<u:GetGenericHostEntry xmlns:u="urn:dslforum-org:service:Hosts:1">' +
                        '<NewIndex>' + i + '</NewIndex></u:GetGenericHostEntry>', u, pw);
                    const dev = {
                        mac:    parseXml(r, 'NewMACAddress')    || '',
                        ip:     parseXml(r, 'NewIPAddress')     || '',
                        name:   parseXml(r, 'NewHostName')      || 'Unbekannt',
                        active: parseXml(r, 'NewActive')        === '1',
                        iface:  parseXml(r, 'NewInterfaceType') || ''
                    };
                    if (dev.mac) devices.push(dev);
                } catch (_) {}
            }

            this._cache.devices = devices;

            for (const dev of devices) {
                const pre = 'devices.' + dev.mac.replace(/:/g, '_');
                // Device-Channel anlegen
                try {
                    await this.extendObjectAsync('devices', {
                        type: 'folder', common: { name: 'Netzwerkgeraete' }, native: {}
                    });
                    await this.extendObjectAsync(pre, {
                        type: 'channel', common: { name: dev.name || dev.mac }, native: {}
                    });
                } catch (_) {}
                for (const [k, t, v, rl] of [
                    ['name',   'string',  dev.name,   'text'],
                    ['ip',     'string',  dev.ip,     'text'],
                    ['mac',    'string',  dev.mac,    'text'],
                    ['active', 'boolean', dev.active, 'indicator'],
                    ['iface',  'string',  dev.iface,  'text']
                ]) {
                    try {
                        await this.extendObjectAsync(pre + '.' + k, {
                            type: 'state',
                            common: { name: k, type: t, role: rl, read: true, write: false },
                            native: {}
                        });
                        await this.setStateAsync(pre + '.' + k, { val: v, ack: true });
                    } catch (_) {}
                }
            }

            this._log('INFO', 'HOSTS', count + ' Ger\u00e4te, ' +
                devices.filter(d => d.active).length + ' aktiv.');
        } catch (e) { this._log('WARN', 'TR064', 'Hosts: ' + e.message); }
    }

    async _pollWg() {
        const s = await wgStatus('wg-fritzwireguard');
        this._cache.wg = s;
        await this.setStateAsync('wireguard.status', { val: s.connected ? 'connected' : 'disconnected', ack: true });
        if (s.connected && s.peers[0]) {
            const p = s.peers[0];
            await this.setStateAsync('wireguard.handshake', { val: p.handshake, ack: true });
            await this.setStateAsync('wireguard.rxBytes',   { val: p.rx,        ack: true });
            await this.setStateAsync('wireguard.txBytes',   { val: p.tx,        ack: true });
        }
        return s.connected;
    }

    async _poll() {
        try {
            const ok = await this._pollWg();
            if (ok) {
                await this._pollFritzBox();
                await this.setStateAsync('info.connection', { val: true, ack: true });
                await this.setStateAsync('info.lastUpdate', { val: new Date().toISOString(), ack: true });
            } else {
                await this.setStateAsync('info.connection', { val: false, ack: true });
                if (this.config.autoReconnect) {
                    this._log('WARN', 'WG', 'Verbindung verloren \u2014 Reconnect \u2026');
                    await this._connectWg();
                }
            }
        } catch (e) { this._log('ERROR', 'POLL', e.message); }
    }

    // HTTP Server
    _startServer() {
        const port = parseInt(this.config.webPort) || 8094;
        this._server = http.createServer(async (req, res) => {
            const p = url.parse(req.url, true);
            const n = p.pathname;

            if (n === '/api/ping')
                return this._json(res, { ok: true, adapter: 'fritzwireguard', version: this._version() });

            if (n === '/api/status')
                return this._json(res, { wg: this._cache.wg, fritzbox: this._cache.fritzbox, devices: this._cache.devices });

            if (n === '/api/tunnels')
                return this._json(res, this._tunnelMgr.statusAll(this.config.tunnels || []));

            if (n === '/api/tunnels/restart' && req.method === 'POST') {
                this._tunnelMgr.stopAll();
                this._tunnelMgr.startAll(this.config.tunnels || []);
                return this._json(res, { ok: true });
            }

            if (n === '/api/logs') {
                const lv  = (p.query.level    || '').toUpperCase();
                const cat = (p.query.category || '').toUpperCase();
                let logs  = this._logBuffer.slice(0, parseInt(p.query.n) || 200);
                if (lv)  logs = logs.filter(l => l.level    === lv);
                if (cat) logs = logs.filter(l => l.category === cat);
                return this._json(res, logs);
            }

            if (n === '/api/connect'    && req.method === 'POST') return this._json(res, { ok: await this._connectWg() });
            if (n === '/api/disconnect' && req.method === 'POST') { await this._disconnectWg(); return this._json(res, { ok: true }); }
            if (n === '/api/poll'       && req.method === 'POST') { await this._poll(); return this._json(res, { ok: true }); }
            if (n === '/api/version')   return this._json(res, { installed: this._version(), name: 'fritzwireguard' });

            if (n === '/' || n === '/index.html') {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                return res.end(this._buildUI());
            }
            res.writeHead(404); res.end('Not found');
        });
        this._server.listen(port, () => {
            this._log('SYSTEM', 'SYSTEM', 'FritzWireguard v' + this._version() + ' \u2014 Port ' + port);
        });
    }

    _json(res, obj) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

    _version() { try { return require('./package.json').version; } catch (_) { return '0.2.4'; } }

    // ── Web-UI ────────────────────────────────────────────────────────────────
    _buildUI() {
        const v = this._version();
        const CSS =
':root{--bg:#0e1628;--card:#1a2744;--border:#243560;--primary:#2196F3;--accent:#00bcd4;' +
'--green:#4caf50;--red:#f44336;--yellow:#ff9800;--text:#e8eaf6;--muted:#8899bb;}' +
'*{box-sizing:border-box;margin:0;padding:0;}' +
'body{background:var(--bg);color:var(--text);font-family:"Segoe UI",sans-serif;min-height:100vh;}' +
'header{background:linear-gradient(135deg,#0a1020,#1a2744 50%,#0d1f3c);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px;}' +
'.logo{width:40px;height:40px;background:linear-gradient(135deg,var(--primary),var(--accent));border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;}' +
'.title{font-size:1.4rem;font-weight:700;background:linear-gradient(90deg,var(--primary),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}' +
'.subtitle{font-size:0.78rem;color:var(--muted);}' +
'.ver{margin-left:auto;background:var(--card);border:1px solid var(--border);border-radius:20px;padding:4px 12px;font-size:0.75rem;color:var(--muted);}' +
'.pill{width:10px;height:10px;border-radius:50%;background:var(--red);box-shadow:0 0 6px var(--red);display:inline-block;margin-right:8px;}' +
'.pill.on{background:var(--green);box-shadow:0 0 6px var(--green);}' +
'nav{background:var(--card);border-bottom:1px solid var(--border);display:flex;padding:0 24px;flex-wrap:wrap;}' +
'nav button{background:none;border:none;color:var(--muted);padding:14px 18px;cursor:pointer;font-size:0.9rem;border-bottom:3px solid transparent;transition:all .2s;}' +
'nav button.active{color:var(--primary);border-bottom-color:var(--primary);}nav button:hover{color:var(--text);}' +
'.tab{display:none;padding:24px;max-width:1200px;margin:0 auto;}.tab.active{display:block;}' +
'.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:16px;margin-bottom:24px;}' +
'.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;}' +
'.ct{font-size:0.75rem;text-transform:uppercase;color:var(--muted);letter-spacing:.08em;margin-bottom:8px;}' +
'.cv{font-size:1.5rem;font-weight:700;}.cv.green{color:var(--green);}.cv.red{color:var(--red);}' +
'.cs{font-size:0.78rem;color:var(--muted);margin-top:4px;}' +
'table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;margin-bottom:20px;}' +
'th{background:#1f2f50;color:var(--muted);font-size:0.75rem;text-transform:uppercase;padding:12px 16px;text-align:left;letter-spacing:.06em;}' +
'td{padding:12px 16px;border-top:1px solid var(--border);font-size:0.88rem;}tr:hover td{background:rgba(33,150,243,.05);}' +
'.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.73rem;font-weight:600;}' +
'.badge.active,.badge.running{background:rgba(76,175,80,.18);color:var(--green);}' +
'.badge.inactive,.badge.stopped{background:rgba(244,67,54,.18);color:var(--red);}' +
'.badge.warn{background:rgba(255,152,0,.18);color:var(--yellow);}' +
'.log-area{background:#080f1e;border:1px solid var(--border);border-radius:10px;height:500px;overflow-y:auto;padding:12px;font-family:monospace;font-size:0.8rem;}' +
'.log-entry{padding:3px 0;border-bottom:1px solid rgba(36,53,96,.4);}' +
'.log-entry .ts{color:#556;margin-right:8px;}.log-entry .cat{color:var(--accent);margin-right:8px;}' +
'.log-entry.ERROR .msg{color:var(--red);}.log-entry.WARN .msg{color:var(--yellow);}.log-entry.SYSTEM .msg{color:var(--primary);}' +
'.ltb{display:flex;gap:10px;margin-bottom:12px;align-items:center;flex-wrap:wrap;}' +
'.ltb select,.ltb button{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 12px;cursor:pointer;}' +
'.btn{background:var(--primary);color:#fff;border:none;border-radius:8px;padding:10px 20px;cursor:pointer;font-size:0.88rem;font-weight:600;transition:opacity .2s;}' +
'.btn:hover{opacity:.85;}.btn.red{background:var(--red);}.btn.green{background:var(--green);}' +
'.btn-row{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap;}' +
'.ig{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;}' +
'.ir{display:flex;justify-content:space-between;padding:8px 12px;background:#0e1628;border-radius:6px;font-size:0.85rem;}' +
'.ir .k{color:var(--muted);}.ir .v{color:var(--text);font-weight:600;}' +
'#wgbar{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:24px;display:flex;align-items:center;gap:12px;}' +
'.sl{font-size:0.75rem;text-transform:uppercase;color:var(--muted);letter-spacing:.08em;margin-bottom:12px;margin-top:8px;}' +
'.hint{background:rgba(33,150,243,.08);border:1px solid rgba(33,150,243,.25);border-radius:10px;padding:16px 20px;margin-bottom:20px;font-size:0.85rem;line-height:1.7;}' +
'.hint code{background:#0e1628;border-radius:4px;padding:2px 6px;color:var(--accent);font-family:monospace;}';

        const JS =
'function showTab(n){' +
'  document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active");});' +
'  document.querySelectorAll("nav button").forEach(function(b){b.classList.remove("active");});' +
'  var el=document.getElementById("tab-"+n);if(el)el.classList.add("active");' +
'  var btn=document.getElementById("tb-"+n);if(btn)btn.classList.add("active");' +
'  if(n==="logs")loadLogs();if(n==="tunnel")loadTunnels();' +
'}' +
'function fmt(b){if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";return (b/1048576).toFixed(2)+" MB";}' +
'function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}' +
'function card(t,v,sub,cls){return "<div class=\'card\'><div class=\'ct\'>"+t+"</div><div class=\'cv "+(cls||"")+"\'>"+v+"</div>"+(sub?"<div class=\'cs\'>"+sub+"</div>":"")+"</div>";}' +
'function ir(k,v){return "<div class=\'ir\'><span class=\'k\'>"+k+"</span><span class=\'v\'>"+v+"</span></div>";}' +
'async function loadStatus(){' +
'  try{var r=await fetch("/api/status");var d=await r.json();' +
'  var wg=d.wg||{};var fb=d.fritzbox||{};var devs=d.devices||[];' +
'  var pill=document.getElementById("wg-pill");var txt=document.getElementById("wg-txt");' +
'  if(wg.connected){pill.className="pill on";txt.textContent="WireGuard verbunden";}' +
'  else{pill.className="pill";txt.textContent="WireGuard getrennt";}' +
'  document.getElementById("lu").textContent="Stand: "+new Date().toLocaleTimeString();' +
'  var wgC="";var peer=wg.peers&&wg.peers[0]?wg.peers[0]:{};' +
'  wgC+=card("Status",wg.connected?"Verbunden":"Getrennt","",wg.connected?"green":"red");' +
'  if(peer.handshake)wgC+=card("Letzter Handshake",peer.handshake,"","");' +
'  if(peer.rx!=null)wgC+=card("Empfangen",fmt(peer.rx),"","");' +
'  if(peer.tx!=null)wgC+=card("Gesendet",fmt(peer.tx),"","");' +
'  document.getElementById("cards-wg").innerHTML=wgC;' +
'  var fbC="";' +
'  if(fb.externalIP)fbC+=card("Externe IP",fb.externalIP,"","");' +
'  if(fb.modelName)fbC+=card("Modell",fb.modelName,"","");' +
'  if(fb.firmwareVersion)fbC+=card("Firmware",fb.firmwareVersion,"","");' +
'  if(fb.uptime!=null)fbC+=card("Uptime",Math.floor(fb.uptime/3600)+"h "+Math.floor((fb.uptime%3600)/60)+"m","","");' +
'  document.getElementById("cards-fritz").innerHTML=fbC;' +
'  var tb="";devs.sort(function(a,b){return b.active-a.active;}).forEach(function(dv){' +
'    tb+="<tr><td>"+esc(dv.name)+"</td><td>"+esc(dv.ip)+"</td><td style=\'font-family:monospace\'>"+esc(dv.mac)+"</td>"' +
'      +"<td>"+esc(dv.iface)+"</td><td><span class=\'badge "+(dv.active?"active":"inactive")+"\'>"+(dv.active?"Aktiv":"Inaktiv")+"</span></td></tr>";});' +
'  var nb=document.getElementById("nbody");' +
'  if(nb)nb.innerHTML=tb||"<tr><td colspan=\'5\' style=\'text-align:center;color:var(--muted)\'>Keine Ger\u00e4te</td></tr>";' +
'  var si=document.getElementById("sinfo");' +
'  if(si)si.innerHTML=ir("Adapter","FritzWireguard")+ir("Version","' + v + '")' +
'    +ir("Ger\u00e4te",devs.length)+ir("Aktiv",devs.filter(function(dv){return dv.active;}).length);' +
'  }catch(e){console.error(e);}' +
'}' +
'async function loadTunnels(){' +
'  try{var r=await fetch("/api/tunnels");var ts=await r.json();' +
'  var tb="";ts.forEach(function(t){' +
'    var st=t.error?"warn":(t.running?"running":"stopped");' +
'    var stTxt=t.error?"Fehler":(t.running?"Aktiv":"Gestoppt");' +
'    tb+="<tr><td><strong>"+esc(t.name)+"</strong></td>"' +
'      +"<td style=\'font-family:monospace\'>127.0.0.1:"+esc(t.localPort)+"</td>"' +
'      +"<td style=\'font-family:monospace\'>"+esc(t.remoteHost)+":"+esc(t.remotePort)+"</td>"' +
'      +"<td>"+t.active+" / "+t.total+"</td>"' +
'      +"<td>"+fmt(t.rxBytes)+" \u2191 / "+fmt(t.txBytes)+" \u2193</td>"' +
'      +"<td><span class=\'badge "+st+"\'>"+stTxt+"</span>"' +
'      +(t.error?"<br><small style=\'color:var(--red)\'>"+esc(t.error)+"</small>":"")+"</td></tr>";' +
'  });' +
'  var tbody=document.getElementById("tbody-tunnel");' +
'  if(tbody)tbody.innerHTML=tb||"<tr><td colspan=\'6\' style=\'text-align:center;color:var(--muted)\'>Keine Tunnel konfiguriert</td></tr>";}' +
'  catch(e){console.error(e);}' +
'}' +
'async function restartTunnels(){await fetch("/api/tunnels/restart",{method:"POST"});loadTunnels();}' +
'async function loadLogs(){' +
'  var lv=document.getElementById("ll").value;var cat=document.getElementById("lc").value;' +
'  var r=await fetch("/api/logs?n=300&level="+encodeURIComponent(lv)+"&category="+encodeURIComponent(cat));' +
'  var logs=await r.json();' +
'  var html=logs.map(function(l){var d=new Date(l.ts);' +
'    return "<div class=\'log-entry "+(l.level||"")+"\'><span class=\'ts\'>"+d.toLocaleDateString()+" "+d.toLocaleTimeString()+"</span>"' +
'      +"<span class=\'cat\'>"+esc(l.category)+"</span><span class=\'msg\'>"+esc(l.msg)+"</span></div>";}).join("");' +
'  var la=document.getElementById("la");la.innerHTML=html||"<span style=\'color:var(--muted)\'>Keine Eintr\u00e4ge</span>";' +
'  if(document.getElementById("lauto").checked)la.scrollTop=la.scrollHeight;}' +
'function exportLogs(){var blob=new Blob([document.getElementById("la").innerText],{type:"text/plain"});' +
'  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="fritzwireguard-logs.txt";a.click();}' +
'async function wgConnect(){document.getElementById("smsg").textContent="Verbinde\u2026";' +
'  var d=await(await fetch("/api/connect",{method:"POST"})).json();' +
'  document.getElementById("smsg").textContent=d.ok?"Verbunden.":"Fehler.";loadStatus();}' +
'async function wgDisconnect(){document.getElementById("smsg").textContent="Trenne\u2026";' +
'  await fetch("/api/disconnect",{method:"POST"});document.getElementById("smsg").textContent="Getrennt.";loadStatus();}' +
'async function forcePoll(){document.getElementById("smsg").textContent="Abfrage\u2026";' +
'  await fetch("/api/poll",{method:"POST"});document.getElementById("smsg").textContent="Fertig.";loadStatus();}' +
'loadStatus();setInterval(loadStatus,30000);';

        return '<!DOCTYPE html><html lang="de"><head>' +
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
'<title>FritzWireguard</title><style>' + CSS + '</style></head><body>' +
'<header><div class="logo">\uD83D\uDD12</div>' +
'<div><div class="title">FritzWireguard</div><div class="subtitle">WireGuard VPN \u2192 FritzBox</div></div>' +
'<div class="ver">v' + v + '</div></header>' +
'<nav>' +
'<button id="tb-daten"  class="active" onclick="showTab(\'daten\')">&#128202; Daten</button>' +
'<button id="tb-nodes"  onclick="showTab(\'nodes\')">&#128268; Nodes</button>' +
'<button id="tb-tunnel" onclick="showTab(\'tunnel\')">&#128260; Tunnel</button>' +
'<button id="tb-logs"   onclick="showTab(\'logs\')">&#128203; Logs</button>' +
'<button id="tb-system" onclick="showTab(\'system\')">&#9881;&#65039; System</button>' +
'</nav>' +

// TAB: DATEN
'<div class="tab active" id="tab-daten">' +
'<div id="wgbar"><span class="pill" id="wg-pill"></span><strong id="wg-txt">Lade\u2026</strong>' +
'<span style="margin-left:auto;color:var(--muted);font-size:0.8rem" id="lu"></span></div>' +
'<div class="sl">WireGuard</div><div class="cards" id="cards-wg"></div>' +
'<div class="sl">FritzBox</div><div class="cards" id="cards-fritz"></div>' +
'</div>' +

// TAB: NODES
'<div class="tab" id="tab-nodes">' +
'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
'<h2 style="font-size:1rem;color:var(--muted);">Netzwerkger\u00e4te im entfernten Netz</h2>' +
'<button class="btn" onclick="loadStatus()">&#8635; Aktualisieren</button></div>' +
'<table><thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Interface</th><th>Status</th></tr></thead>' +
'<tbody id="nbody"><tr><td colspan="5" style="text-align:center;color:var(--muted)">Lade\u2026</td></tr></tbody></table>' +
'</div>' +

// TAB: TUNNEL
'<div class="tab" id="tab-tunnel">' +
'<div class="hint"><strong style="color:var(--primary)">&#128260; TCP Port-Weiterleitung durch den VPN-Tunnel</strong><br>' +
'Jeder Tunnel \u00f6ffnet einen Port auf <code>127.0.0.1</code> und leitet alle Verbindungen transparent durch WireGuard weiter.<br>' +
'Andere ioBroker-Adapter konfigurierst du mit <code>127.0.0.1:&lt;lokalerPort&gt;</code> als Adresse.<br>' +
'Der restliche Netzwerkverkehr (alle anderen Adapter) bleibt im lokalen Netz \u2014 kein Full-Tunnel.<br><br>' +
'<strong>Beispiel Kostal Piko:</strong> Wechselrichter auf <code>192.168.178.55</code> im entfernten Netz &rarr; ' +
'Tunnel <code>127.0.0.1:8085 \u2192 192.168.178.55:80</code> &rarr; Kostal-Adapter auf <code>127.0.0.1:8085</code> setzen.' +
'</div>' +
'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
'<div class="sl" style="margin:0">Konfigurierte Tunnel</div>' +
'<button class="btn" onclick="restartTunnels()">&#8635; Tunnel neu starten</button></div>' +
'<table><thead><tr><th>Name</th><th>Lokaler Port</th><th>Ziel (Remote)</th>' +
'<th>Verbindungen</th><th>Traffic \u2191\u2193</th><th>Status</th></tr></thead>' +
'<tbody id="tbody-tunnel"><tr><td colspan="6" style="text-align:center;color:var(--muted)">Lade\u2026</td></tr></tbody></table>' +
'<p style="font-size:0.82rem;color:var(--muted)">Tunnel werden in der Adapter-Konfiguration (ioBroker Admin \u2192 Instanz) eingerichtet.</p>' +
'</div>' +

// TAB: LOGS
'<div class="tab" id="tab-logs">' +
'<div class="ltb">' +
'<select id="ll"><option value="">Alle Level</option>' +
'<option>SYSTEM</option><option>INFO</option><option>WARN</option><option>ERROR</option></select>' +
'<select id="lc"><option value="">Alle Kategorien</option>' +
'<option value="WG">WireGuard</option><option value="TR064">TR-064</option>' +
'<option value="HOSTS">Hosts</option><option value="TUNNEL">Tunnel</option>' +
'<option value="POLL">Poll</option><option value="SYSTEM">System</option></select>' +
'<button onclick="loadLogs()">&#8635; Neu laden</button>' +
'<button onclick="exportLogs()">&#8595; Export</button>' +
'<label style="margin-left:auto;font-size:0.8rem;display:flex;gap:6px;align-items:center;">' +
'<input type="checkbox" id="lauto" checked> Auto-Scroll</label>' +
'</div><div class="log-area" id="la"></div></div>' +

// TAB: SYSTEM
'<div class="tab" id="tab-system">' +
'<div class="card" style="margin-bottom:20px;"><div class="ct">WireGuard Steuerung</div>' +
'<div class="btn-row">' +
'<button class="btn green" onclick="wgConnect()">Verbinden</button>' +
'<button class="btn red"   onclick="wgDisconnect()">Trennen</button>' +
'<button class="btn"       onclick="forcePoll()">&#8635; Jetzt abfragen</button>' +
'</div><div id="smsg" style="margin-top:12px;font-size:0.85rem;color:var(--muted);"></div></div>' +
'<div class="card"><div class="ct">Adapter-Info</div><div class="ig" id="sinfo"></div></div>' +
'</div>' +

'<script>' + JS + '</script></body></html>';
    }

    // Lifecycle
    async onReady() {
        try {
            this._log('SYSTEM', 'SYSTEM', 'FritzWireguard v' + this._version() + ' startet \u2026');
            await this._initStates();

            this._tunnelMgr = new TunnelManager(this._log.bind(this));
            this._tunnelMgr.startAll(this.config.tunnels || []);

            this._startServer();
            if (this.config.autoConnect) await this._connectWg();
            await this._poll();

            const iv = Math.max(30, parseInt(this.config.pollInterval) || 60);
            this._pollTimer = setInterval(() => this._poll(), iv * 1000);
        } catch (e) {
            this._log('ERROR', 'SYSTEM', 'Kritischer Fehler in onReady: ' + e.message);
        }
    }
    onStateChange(id, state) {
        if (state && !state.ack) this._log('INFO', 'STATE', id + ' = ' + state.val);
    }

    onUnload(callback) {
        // Sicherheits-Timeout: callback IMMER nach 3s aufrufen
        // verhindert SIGKILL durch ioBroker bei haengendem onUnload
        const done = (() => {
            let called = false;
            return () => { if (!called) { called = true; callback(); } };
        })();
        const safetyTimer = setTimeout(done, 8000); // stopTimeout=10s, wir rufen vorher auf

        (async () => {
            try {
                if (this._pollTimer) clearInterval(this._pollTimer);
                if (this._tunnelMgr) this._tunnelMgr.stopAll();

                // HTTP-Server: alle Verbindungen aktiv schliessen
                if (this._server) {
                    try {
                        // Node 18+ hat closeAllConnections()
                        if (typeof this._server.closeAllConnections === 'function') {
                            this._server.closeAllConnections();
                        }
                        this._server.close();
                    } catch (_) {}
                }

                // WireGuard trennen (mit eigenem Timeout)
                const wgDisconnect = this.config && this.config.wgDisconnectOnStop;
                if (wgDisconnect) {
                    await Promise.race([
                        this._disconnectWg(),
                        new Promise(r => setTimeout(r, 3000))
                    ]);
                }

                // Temp-Config loeschen
                if (this._wgCfgPath && fs.existsSync(this._wgCfgPath)) {
                    try { fs.unlinkSync(this._wgCfgPath); } catch (_) {}
                }
            } catch (e) {
                const l = this.log;
                if (l) l.warn('[SYSTEM] onUnload Fehler: ' + e.message);
            } finally {
                clearTimeout(safetyTimer);
                done();
            }
        })();
    }
}

if (require.main !== module) {
    module.exports = options => new FritzWireguard(options);
} else {
    new FritzWireguard();
}
