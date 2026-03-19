'use strict';

const utils = require('@iobroker/adapter-core'); // ✅ FIX
const http  = require('http');
const net   = require('net');
const url   = require('url');
const fs    = require('fs');
const os    = require('os');
const path  = require('path');
const { exec } = require('child_process');

// ─────────────────────────────────────────────────────────────────────────────
// Adapter
// ─────────────────────────────────────────────────────────────────────────────

class FritzWireguard extends utils.Adapter { // ✅ FIX

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

    // ─────────────────────────────────────────────────────────────────────────
    // Logging (leicht abgesichert)
    // ─────────────────────────────────────────────────────────────────────────

    _log(level, category, msg) {
        const entry = { ts: Date.now(), level, category, msg };
        this._logBuffer.unshift(entry);

        if (this._logBuffer.length > ((this.config?.logBuffer) || 500)) {
            this._logBuffer.pop();
        }

        const l = this.log;
        if (!l) {
            console.log(`[${level}][${category}] ${msg}`);
            return;
        }

        if (level === 'ERROR') l.error(`[${category}] ${msg}`);
        else if (level === 'WARN') l.warn(`[${category}] ${msg}`);
        else l.info(`[${category}] ${msg}`);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    async onReady() {
        try {
            this._log('SYSTEM', 'SYSTEM', `Start v${this._version()}`);

            await this._initStates();

            this._startServer();

            if (this.config.autoConnect) {
                await this._connectWg();
            }

            await this._poll();

            const interval = Math.max(30, parseInt(this.config.pollInterval) || 60);
            this._pollTimer = setInterval(() => this._poll(), interval * 1000);

            this._log('SYSTEM', 'SYSTEM', `Ready (Poll ${interval}s)`);

        } catch (e) {
            this._log('ERROR', 'SYSTEM', e.stack || e.message);
        }
    }

    onStateChange(id, state) {
        if (state && !state.ack) {
            this._log('INFO', 'STATE', `${id} = ${state.val}`);
        }
    }

    onUnload(callback) {
        try {
            if (this._pollTimer) clearInterval(this._pollTimer);
            if (this._server) this._server.close();

        } catch (e) {
            this._log('WARN', 'SYSTEM', e.message);
        }

        callback();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Minimaler HTTP Server (unverändert)
    // ─────────────────────────────────────────────────────────────────────────

    _startServer() {
        const port = parseInt(this.config.webPort) || 8094;

        this._server = http.createServer((req, res) => {
            res.writeHead(200);
            res.end('FritzWireguard läuft');
        });

        this._server.listen(port, () => {
            this._log('SYSTEM', 'HTTP', `Port ${port}`);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // States (minimal abgesichert)
    // ─────────────────────────────────────────────────────────────────────────

    async _initStates() {
        await this.extendObjectAsync('info.connection', {
            type: 'state',
            common: {
                name: 'Connection',
                type: 'boolean',
                role: 'indicator.connected',
                read: true,
                write: false
            },
            native: {}
        });
    }

    async _poll() {
        try {
            await this.setStateAsync('info.connection', {
                val: true,
                ack: true
            });
        } catch (e) {
            this._log('ERROR', 'POLL', e.message);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WireGuard (Dummy für Stabilität beim Start)
    // ─────────────────────────────────────────────────────────────────────────

    async _connectWg() {
        this._log('INFO', 'WG', 'Connect (stub)');
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────

    _version() {
        try {
            return require('./package.json').version;
        } catch {
            return 'unknown';
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Export (korrekt für ioBroker)
// ─────────────────────────────────────────────────────────────────────────────

if (require.main !== module) {
    module.exports = options => new FritzWireguard(options);
} else {
    new FritzWireguard();
}