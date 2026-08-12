const { contextBridge, ipcRenderer } = require('electron');

// Brücke für den lokalen Sync-Server (main-Prozess): der Main-Prozess ist
// hier der Initiator (eingehender HTTP-Request vom iPad), daher gibt es kein
// eingebautes ipcMain.invoke-Gegenstück — stattdessen ein Request/Reply-Muster
// mit Korrelations-ID über webContents.send/ipcRenderer.send.
contextBridge.exposeInMainWorld('apexSyncBridge', {
  onRequest(channel, handler) {
    ipcRenderer.on(channel, async (_event, msg) => {
      let result, error = null;
      try { result = await handler(msg.payload); }
      catch (e) { error = String((e && e.message) || e); }
      ipcRenderer.send(channel + ':reply', { reqId: msg.reqId, result, error });
    });
  },
  onServerInfo(cb) {
    ipcRenderer.on('apex:server-info', (_event, info) => cb(info));
  }
});
