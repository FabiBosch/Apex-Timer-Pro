const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const selfsigned = require('selfsigned');
const { app } = require('electron');

var DAY_MS = 24 * 60 * 60 * 1000;

function certDir() {
  return path.join(app.getPath('userData'), 'certs');
}

function readMeta(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')); }
  catch (e) { return {}; }
}
function writeMeta(dir, meta) {
  fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(meta, null, 2));
}

function readPemPair(dir, certFile, keyFile) {
  try {
    return {
      certPem: fs.readFileSync(path.join(dir, certFile), 'utf8'),
      keyPem: fs.readFileSync(path.join(dir, keyFile), 'utf8')
    };
  } catch (e) { return null; }
}
function writePemPair(dir, certFile, keyFile, pems) {
  fs.writeFileSync(path.join(dir, certFile), pems.certPem);
  fs.writeFileSync(path.join(dir, keyFile), pems.keyPem);
}

// Node's eingebautes crypto.X509Certificate statt eigener Zeitstempel-
// Buchhaltung — robust, keine Doppelbuchhaltung nötig.
function isExpiringSoon(certPem, withinDays) {
  try {
    var x = new crypto.X509Certificate(certPem);
    return (new Date(x.validTo).getTime() - Date.now()) < withinDays * DAY_MS;
  } catch (e) { return true; } // unlesbar -> sicherheitshalber neu erzeugen
}

// Root-CA: langlebig (10 Jahre), wird EINMALIG auf dem iPad installiert/
// vertraut. KEIN serverAuth-EKU (iOS erwartet strukturell getrennte
// Root-CA und Server-Leaf, siehe Plan-Kommentar in local-server.js).
async function generateCa() {
  var pems = await selfsigned.generate(
    [{ name: 'commonName', value: 'Apex Timer Pro Local CA' }],
    {
      algorithm: 'sha256',
      keySize: 2048,
      notAfterDate: new Date(Date.now() + 3650 * DAY_MS),
      extensions: [
        { name: 'basicConstraints', cA: true, critical: true },
        { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }
      ]
    }
  );
  return { certPem: pems.cert, keyPem: pems.private };
}

// Server-Leaf, von der Root-CA signiert. Max. 825 Tage Gültigkeit (Apple-
// Vorgabe für vertraute TLS-Server-Zertifikate), SAN mit der aktuellen
// LAN-IP — kann bei IP-Wechsel (DHCP) jederzeit mit demselben CA-Key neu
// ausgestellt werden, OHNE dass das iPad das Profil erneut installieren
// muss (die vertraute Root-CA bleibt gleich).
async function generateServerCert(ca, ip) {
  var pems = await selfsigned.generate(
    [{ name: 'commonName', value: ip }],
    {
      algorithm: 'sha256',
      keySize: 2048,
      notAfterDate: new Date(Date.now() + 820 * DAY_MS),
      ca: { cert: ca.certPem, key: ca.keyPem },
      extensions: [
        { name: 'basicConstraints', cA: false, critical: true },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: [
          { type: 2, value: 'localhost' },
          { type: 7, ip: ip },
          { type: 7, ip: '127.0.0.1' }
        ] }
      ]
    }
  );
  return { certPem: pems.cert, keyPem: pems.private };
}

// Stellt sicher, dass eine gültige CA + ein für die aktuelle IP gültiges
// Server-Zertifikat existieren, erzeugt/erneuert bei Bedarf. Gibt zurück,
// ob das iPad-Profil (neu) installiert werden muss — nur bei einer NEUEN
// Root-CA der Fall (erster Start oder verlorene/korrupte Zertifikate),
// nicht bei einem reinen IP-Wechsel.
async function ensureCertificates(currentIp) {
  var dir = certDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  var meta = readMeta(dir);
  var caReinstallNeeded = false;
  var ca = readPemPair(dir, 'ca-cert.pem', 'ca-key.pem');

  if (!ca || !meta.profileUUID || !meta.certPayloadUUID || isExpiringSoon(ca.certPem, 60)) {
    ca = await generateCa();
    writePemPair(dir, 'ca-cert.pem', 'ca-key.pem', ca);
    meta.profileUUID = crypto.randomUUID();
    meta.certPayloadUUID = crypto.randomUUID();
    meta.serverIp = null; // Server-Leaf muss mit der neuen CA neu signiert werden
    caReinstallNeeded = true;
  }

  var server = readPemPair(dir, 'server-cert.pem', 'server-key.pem');
  var needsServerRegen = !server || meta.serverIp !== currentIp || isExpiringSoon(server.certPem, 30);
  if (needsServerRegen) {
    server = await generateServerCert(ca, currentIp);
    writePemPair(dir, 'server-cert.pem', 'server-key.pem', server);
    meta.serverIp = currentIp;
  }

  writeMeta(dir, meta);

  return {
    ca: ca,
    server: server,
    caReinstallNeeded: caReinstallNeeded,
    profileUUID: meta.profileUUID,
    certPayloadUUID: meta.certPayloadUUID
  };
}

function pemToBase64Der(pem) {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
}
function wrapBase64(b64, width) {
  var lines = [];
  for (var i = 0; i < b64.length; i += width) lines.push(b64.slice(i, i + width));
  return lines.join('\n      ');
}

// Apple-Konfigurationsprofil (.mobileconfig) mit dem CA-Root-Zertifikat als
// Payload — löst in Safari auf iOS automatisch den "Profil installieren"-
// Dialog aus (Content-Type application/x-apple-aspen-config beim Ausliefern
// nicht vergessen, siehe local-server.js). PayloadUUID/-Identifier bleiben
// über meta.json stabil, damit iOS ein bestehendes Profil ersetzt statt es
// zu duplizieren, wenn der Nutzer die Adresse erneut öffnet.
function buildMobileConfig(opts) {
  var der64 = wrapBase64(pemToBase64Der(opts.caCertPem), 76);
  return '<?xml version="1.0" encoding="UTF-8"?>\n'
    + '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    + '<plist version="1.0">\n'
    + '<dict>\n'
    + '  <key>PayloadContent</key>\n'
    + '  <array>\n'
    + '    <dict>\n'
    + '      <key>PayloadCertificateFileName</key>\n'
    + '      <string>apex-timer-pro-ca.cer</string>\n'
    + '      <key>PayloadContent</key>\n'
    + '      <data>\n'
    + '      ' + der64 + '\n'
    + '      </data>\n'
    + '      <key>PayloadDescription</key>\n'
    + '      <string>Installiert das lokale Root-Zertifikat von Apex Timer Pro (PC: ' + opts.ip + '), damit dieses Gerät der HTTPS-Verbindung im selben WLAN vertraut.</string>\n'
    + '      <key>PayloadDisplayName</key>\n'
    + '      <string>Apex Timer Pro – Lokales Zertifikat</string>\n'
    + '      <key>PayloadIdentifier</key>\n'
    + '      <string>com.fabi.apextimerpro.cert.' + opts.certPayloadUUID + '</string>\n'
    + '      <key>PayloadType</key>\n'
    + '      <string>com.apple.security.root</string>\n'
    + '      <key>PayloadUUID</key>\n'
    + '      <string>' + opts.certPayloadUUID + '</string>\n'
    + '      <key>PayloadVersion</key>\n'
    + '      <integer>1</integer>\n'
    + '    </dict>\n'
    + '  </array>\n'
    + '  <key>PayloadDescription</key>\n'
    + '  <string>Vertrauenswürdiges lokales Zertifikat für die Verbindung zwischen iPad und PC im selben WLAN (Apex Timer Pro).</string>\n'
    + '  <key>PayloadDisplayName</key>\n'
    + '  <string>Apex Timer Pro – Lokales Zertifikat</string>\n'
    + '  <key>PayloadIdentifier</key>\n'
    + '  <string>com.fabi.apextimerpro.certprofile</string>\n'
    + '  <key>PayloadOrganization</key>\n'
    + '  <string>Apex Timer Pro</string>\n'
    + '  <key>PayloadRemovalDisallowed</key>\n'
    + '  <false/>\n'
    + '  <key>PayloadType</key>\n'
    + '  <string>Configuration</string>\n'
    + '  <key>PayloadUUID</key>\n'
    + '  <string>' + opts.profileUUID + '</string>\n'
    + '  <key>PayloadVersion</key>\n'
    + '  <integer>1</integer>\n'
    + '</dict>\n'
    + '</plist>\n';
}

module.exports = { ensureCertificates: ensureCertificates, buildMobileConfig: buildMobileConfig, certDir: certDir };
