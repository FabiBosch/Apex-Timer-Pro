const { app, BrowserWindow } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const { startLocalServer } = require('./local-server');

// Umgeht ERR_HTTP2_SERVER_REFUSED_STREAM beim Auto-Update-Check — tritt bei
// manchen VPN-Tunneln/Netzwerkadaptern (z.B. NordLynx/WireGuard) auf, wenn
// Chromiums HTTP/2-Verbindung zu GitHub durch den Tunnel läuft. Erzwingt
// HTTP/1.1 für alle Electron-Netzwerkanfragen — muss vor app.whenReady()
// gesetzt werden. Betrifft nur ausgehende Internet-Verbindungen (Updater),
// nicht die lokale Sync (die läuft separat über Node's http/https-Module
// in local-server.js).
app.commandLine.appendSwitch('disable-http2');

// Der Update-Check läuft komplett unsichtbar im Hintergrund (kein Fenster,
// keine Konsole in der installierten App) — ohne Log lässt sich ein
// Fehlschlag nicht diagnostizieren. Einfache Textdatei statt zusätzlicher
// Logging-Dependency, reicht für dieses Ein-Nutzer-Projekt völlig aus.
var updateLogPath = path.join(app.getPath('userData'), 'update-log.txt');
function logUpdate(line) {
  try {
    fs.appendFileSync(updateLogPath, '[' + new Date().toISOString() + '] ' + line + '\n');
  } catch (e) {}
}
autoUpdater.on('checking-for-update', () => logUpdate('Suche nach Updates… (aktuelle Version: ' + app.getVersion() + ')'));
autoUpdater.on('update-available', (info) => logUpdate('Update verfügbar: ' + info.version));
autoUpdater.on('update-not-available', (info) => logUpdate('Kein Update verfügbar, neueste Version: ' + info.version));
autoUpdater.on('error', (err) => logUpdate('FEHLER: ' + (err && (err.stack || err.message) || err)));
autoUpdater.on('download-progress', (p) => logUpdate('Download läuft: ' + Math.round(p.percent) + '%'));
autoUpdater.on('update-downloaded', (info) => logUpdate('Update heruntergeladen (' + info.version + ') — wird beim nächsten Neustart installiert.'));

// Verhindert, dass wiederholte Neustarts (z.B. beim Testen) den Update-Check
// zu oft auslösen und GitHubs Secondary-Rate-Limit (429 "Too many requests")
// treffen — die blockt danach bis zu einer Stunde JEDEN weiteren Versuch,
// auch legitime. Mindestabstand zwischen zwei Checks, persistiert über
// App-Neustarts hinweg in einer eigenen State-Datei (userData).
var updateStatePath = path.join(app.getPath('userData'), 'update-check-state.json');
var UPDATE_CHECK_MIN_INTERVAL_MS = 60 * 60 * 1000;

function shouldCheckForUpdates() {
  try {
    var state = JSON.parse(fs.readFileSync(updateStatePath, 'utf8'));
    return (Date.now() - (state.lastCheckedAt || 0)) >= UPDATE_CHECK_MIN_INTERVAL_MS;
  } catch (e) {
    return true; // keine/kaputte State-Datei -> darf prüfen
  }
}

function markUpdateChecked() {
  try {
    fs.writeFileSync(updateStatePath, JSON.stringify({ lastCheckedAt: Date.now() }));
  } catch (e) {}
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    autoHideMenuBar: true,
    icon: path.join(__dirname, 'docs', 'icon-512.png'),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  win.loadFile(path.join(__dirname, 'docs', 'index.html'));

  // F11 = echtes Vollbild ohne Fensterrahmen/Titelleiste (win.setFullScreen,
  // nicht die DOM-Fullscreen-API) — muss im Main-Prozess behandelt werden,
  // da nur dieser die BrowserWindow-Fensterdekoration steuern kann.
  win.webContents.on('before-input-event', (event, input) => {
    if (input.type === 'keyDown' && input.key === 'F11') {
      win.setFullScreen(!win.isFullScreen());
      event.preventDefault();
    }
  });

  // Cast-Fenster (Zweitbildschirm, docs/index.html: apexCastToggle()):
  // window.open() aus dem Renderer erzeugt in Electron bereits ein eigenes,
  // frei verschiebbares/skalierbares BrowserWindow — hier wird das nur
  // explizit abgesichert (volle Fensterdekoration, vollbildfähig, kein
  // Parent-Bezug, der das Verschieben auf einen zweiten Monitor einschränken
  // könnte) und F12 als eigener, NUR für dieses Fenster geltender
  // Vollbild-Shortcut ergänzt (analog zu F11 oben fürs Hauptfenster, aber
  // unabhängig davon, da eigenes BrowserWindow mit eigenem Fokus).
  win.webContents.setWindowOpenHandler((details) => {
    if (details.frameName === 'apexCastWindow') {
      return {
        action: 'allow',
        overrideBrowserWindowOptions: {
          width: 1920,
          height: 1080,
          frame: true,
          resizable: true,
          movable: true,
          fullscreenable: true,
          autoHideMenuBar: true,
          parent: undefined,
          webPreferences: { contextIsolation: true, nodeIntegration: false }
        }
      };
    }
    return { action: 'allow' };
  });
  win.webContents.on('did-create-window', (childWindow, details) => {
    if (details.frameName !== 'apexCastWindow') return;
    childWindow.webContents.on('before-input-event', (event, input) => {
      if (input.type === 'keyDown' && input.key === 'F12') {
        childWindow.setFullScreen(!childWindow.isFullScreen());
        event.preventDefault();
      }
    });
  });

  // Lokaler Sync-Server fürs iPad im selben WLAN — läuft unabhängig vom
  // GitHub-Pages/Dropbox-Pfad, siehe local-server.js.
  startLocalServer(win).then((info) => {
    var payload = { ip: info.ip, port: info.port, candidates: info.candidates, protocol: info.protocol, certPort: info.certPort, caReinstallNeeded: info.caReinstallNeeded };
    win.webContents.send('apex:server-info', payload);
    win.webContents.once('did-finish-load', () => {
      win.webContents.send('apex:server-info', payload);
    });
  }).catch((err) => {
    console.error('Lokaler Sync-Server konnte nicht gestartet werden:', err);
  });

  return win;
}

app.whenReady().then(() => {
  createWindow();

  // Nach Updates suchen, sobald die App gestartet ist
  if (shouldCheckForUpdates()) {
    markUpdateChecked();
    autoUpdater.checkForUpdatesAndNotify();
  } else {
    logUpdate('Update-Check übersprungen (letzter Check < 1h her)');
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});