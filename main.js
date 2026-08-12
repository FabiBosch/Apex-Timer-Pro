const { app, BrowserWindow } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const { startLocalServer } = require('./local-server');

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    autoHideMenuBar: true,
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
  startLocalServer(win).then(({ ip, port, candidates }) => {
    win.webContents.send('apex:server-info', { ip, port, candidates });
    win.webContents.once('did-finish-load', () => {
      win.webContents.send('apex:server-info', { ip, port, candidates });
    });
  }).catch((err) => {
    console.error('Lokaler Sync-Server konnte nicht gestartet werden:', err);
  });

  return win;
}

app.whenReady().then(() => {
  createWindow();

  // Nach Updates suchen, sobald die App gestartet ist
  autoUpdater.checkForUpdatesAndNotify();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});