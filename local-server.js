const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { app, ipcMain } = require('electron');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// Grobe Absicherung: der Server ist ausschließlich fürs Heimnetz gedacht,
// kein echtes Auth-System nötig — aber Zugriffe von außerhalb privater
// IP-Bereiche (RFC1918) werden abgelehnt, falls der Port versehentlich von
// außen erreichbar wird (z.B. Router mit UPnP).
function isPrivateAddress(addr) {
  if (!addr) return false;
  var a = addr.replace('::ffff:', '');
  if (a === '::1' || a === '127.0.0.1') return true;
  var m = a.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  var o1 = +m[1], o2 = +m[2];
  return o1 === 10 || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 192 && o2 === 168) || o1 === 127;
}

// Namen typischer VPN-/virtueller Adapter, die zwar eine private IPv4-Adresse
// haben, aber vom iPad im selben WLAN NICHT erreichbar sind (eigenes
// Tunnel-/virtuelles Subnetz) — z.B. NordVPN/NordLynx, WireGuard, Hyper-V,
// WSL, Docker. Solche Adapter dürfen als Sync-Adresse nie bevorzugt werden.
var VIRTUAL_ADAPTER_PATTERN = /nordlynx|nordvpn|wireguard|openvpn|\bvpn\b|\btap\b|\btun\b|virtual|vethernet|hyper-v|docker|wsl|loopback|\bppp\b|zerotier|tailscale|vmware|virtualbox|hamachi|radmin|bluetooth/i;
// Namen typischer physischer Adapter (WLAN/Ethernet) — werden bevorzugt.
var PHYSICAL_ADAPTER_PATTERN = /wlan|wi-?fi|ethernet|\blan\b/i;

// Liefert alle privaten, nicht-internen IPv4-Adressen, sortiert danach, wie
// wahrscheinlich sie vom iPad im selben WLAN erreichbar sind: echte WLAN-/
// Ethernet-Adapter zuerst, bekannte VPN-/virtuelle Adapter zuletzt.
function listLanCandidates() {
  var ifaces = os.networkInterfaces();
  var candidates = [];
  for (var name in ifaces) {
    for (var i = 0; i < ifaces[name].length; i++) {
      var iface = ifaces[name][i];
      if (iface.family === 'IPv4' && !iface.internal) {
        candidates.push({ name: name, address: iface.address });
      }
    }
  }
  candidates.sort(function (a, b) {
    return _adapterRank(a.name) - _adapterRank(b.name);
  });
  return candidates;
}
function _adapterRank(name) {
  if (PHYSICAL_ADAPTER_PATTERN.test(name)) return 0;
  if (VIRTUAL_ADAPTER_PATTERN.test(name)) return 2;
  return 1;
}

function getLanIp() {
  var candidates = listLanCandidates();
  if (candidates.length) return candidates[0].address;
  return '127.0.0.1';
}

// Promise-basiertes Request/Reply zum Renderer über preload.js/apexSyncBridge.
// Der Renderer ist hier passiv (registriert Handler via onRequest), der
// Main-Prozess initiiert jeden einzelnen Austausch.
function requestFromRenderer(win, channel, payload, timeoutMs) {
  return new Promise(function (resolve, reject) {
    if (!win || win.isDestroyed()) { reject(new Error('Fenster nicht verfügbar')); return; }
    var reqId = crypto.randomUUID();
    var replyChannel = channel + ':reply';
    var timer = setTimeout(function () {
      ipcMain.removeListener(replyChannel, onReply);
      reject(new Error('Renderer antwortet nicht (Timeout): ' + channel));
    }, timeoutMs || 8000);
    function onReply(_event, msg) {
      if (msg.reqId !== reqId) return;
      clearTimeout(timer);
      ipcMain.removeListener(replyChannel, onReply);
      if (msg.error) reject(new Error(msg.error)); else resolve(msg.result);
    }
    ipcMain.on(replyChannel, onReply);
    win.webContents.send(channel, { reqId: reqId, payload: payload });
  });
}

function readBody(req, limitBytes) {
  return new Promise(function (resolve, reject) {
    var chunks = [];
    var size = 0;
    req.on('data', function (c) {
      size += c.length;
      if (size > limitBytes) { reject(new Error('Payload zu groß')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', function () { resolve(Buffer.concat(chunks)); });
    req.on('error', reject);
  });
}

function serveStatic(req, res, docsRoot) {
  var urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';
  var filePath = path.normalize(path.join(docsRoot, urlPath));
  if (!filePath.startsWith(docsRoot)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, function (err, data) {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    var ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function startLocalServer(win, preferredPort) {
  var docsRoot = path.join(app.getAppPath(), 'docs');
  var rendererReady = false;
  win.webContents.once('did-finish-load', function () { rendererReady = true; });

  var server = http.createServer(function (req, res) {
    // CORS: die App-Seite und die Sync-API laufen zwar am selben Server,
    // aber der Nutzer kann sie über verschiedene, für den Browser NICHT
    // gleichwertige Adressformen aufrufen (z.B. Seite via LAN-IP geladen,
    // aber "localhost" im Sync-Feld eingetragen) — ohne diese Header
    // scheitert der fetch()-Aufruf dann mit einem Cross-Origin-Fehler.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Apex-Meta');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    var remote = req.socket.remoteAddress;
    if (!isPrivateAddress(remote)) { res.writeHead(403); res.end('Forbidden'); return; }

    var urlPath = req.url.split('?')[0];
    var clipMatch = urlPath.match(/^\/api\/clip\/([^/]+)$/);

    if (req.method === 'POST' && urlPath === '/api/sync') {
      if (!rendererReady) { res.writeHead(503); res.end('Server startet noch'); return; }
      readBody(req, 20 * 1024 * 1024).then(function (buf) {
        var incoming;
        try { incoming = JSON.parse(buf.toString('utf8')); }
        catch (e) { res.writeHead(400); res.end('Ungültiges JSON'); return; }
        requestFromRenderer(win, 'apex:apply-sync', incoming).then(function (result) {
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(result));
        }).catch(function (e) { res.writeHead(500); res.end(String(e.message || e)); });
      }).catch(function (e) { res.writeHead(413); res.end(String(e.message || e)); });
      return;
    }

    if (req.method === 'GET' && clipMatch) {
      if (!rendererReady) { res.writeHead(503); res.end('Server startet noch'); return; }
      requestFromRenderer(win, 'apex:get-clip', { id: clipMatch[1] }).then(function (clip) {
        if (!clip) { res.writeHead(404); res.end('Clip nicht gefunden'); return; }
        res.writeHead(200, { 'Content-Type': clip.mime || 'video/webm' });
        res.end(Buffer.from(clip.buffer));
      }).catch(function (e) { res.writeHead(500); res.end(String(e.message || e)); });
      return;
    }

    if (req.method === 'POST' && clipMatch) {
      if (!rendererReady) { res.writeHead(503); res.end('Server startet noch'); return; }
      readBody(req, 200 * 1024 * 1024).then(function (buf) {
        var mime = req.headers['content-type'] || 'video/webm';
        var meta = {};
        try { meta = JSON.parse(req.headers['x-apex-meta'] || '{}'); } catch (e) {}
        requestFromRenderer(win, 'apex:save-clip', { id: clipMatch[1], buffer: buf, mime: mime, meta: meta }).then(function () {
          res.writeHead(200); res.end('OK');
        }).catch(function (e) { res.writeHead(500); res.end(String(e.message || e)); });
      }).catch(function (e) { res.writeHead(413); res.end(String(e.message || e)); });
      return;
    }

    if (req.method === 'GET') { serveStatic(req, res, docsRoot); return; }
    res.writeHead(404); res.end('Not found');
  });

  return new Promise(function (resolve, reject) {
    var port = preferredPort || 4123;
    var attempts = 0;
    function tryListen() {
      server.once('error', function (err) {
        if (err.code === 'EADDRINUSE' && attempts < 20) {
          attempts++; port++; tryListen();
        } else {
          reject(err);
        }
      });
      server.listen(port, '0.0.0.0', function () {
        resolve({ port: port, ip: getLanIp(), candidates: listLanCandidates(), server: server });
      });
    }
    tryListen();
  });
}

module.exports = { startLocalServer: startLocalServer, getLanIp: getLanIp, listLanCandidates: listLanCandidates };
