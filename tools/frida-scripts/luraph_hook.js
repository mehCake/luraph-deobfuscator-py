'use strict';

const configuredSymbols = new Set();

function sendInfo(type, payload) {
  send(Object.assign({ type }, payload || {}));
}

function sendBuffer(label, ptr, length) {
  try {
    const slice = Memory.readByteArray(ptr, length);
    send({ type: 'buffer', label, length }, slice);
  } catch (err) {
    sendInfo('error', { label, error: err.message || String(err) });
  }
}

function hookSymbol(moduleName, symbolName, handler) {
  let target = null;
  const allModules = Process.enumerateModules();
  const searchModules = moduleName
    ? allModules.filter((mod) => mod.name.toLowerCase().includes(moduleName.toLowerCase()))
    : allModules;
  for (const mod of searchModules) {
    try {
      target = Module.getExportByName(mod.name, symbolName);
      if (target) {
        break;
      }
    } catch (err) {
      continue;
    }
  }
  if (!target) {
    sendInfo('warn', { message: `unable to locate symbol ${symbolName}` });
    return;
  }
  Interceptor.attach(target, handler);
  configuredSymbols.add(symbolName);
  sendInfo('hook', { symbol: symbolName, address: target });
}

function installDefaultHooks() {
  hookSymbol(null, 'LPH_UnpackData', {
    onEnter(args) {
      this.buffer = args[1];
      this.size = args[2].toInt32();
    },
    onLeave(retval) {
      if (this.buffer && this.size > 0) {
        sendBuffer('LPH_UnpackData', this.buffer, this.size);
      }
    },
  });

  hookSymbol(null, 'luaL_loadbufferx', {
    onEnter(args) {
      this.buffer = args[1];
      this.size = args[2].toInt32();
      this.label = 'luaL_loadbufferx';
    },
    onLeave(retval) {
      if (this.buffer && this.size > 0) {
        sendBuffer(this.label, this.buffer, this.size);
      }
    },
  });

  hookSymbol(null, 'luaL_loadbuffer', {
    onEnter(args) {
      this.buffer = args[1];
      this.size = args[2].toInt32();
      this.label = 'luaL_loadbuffer';
    },
    onLeave(retval) {
      if (this.buffer && this.size > 0) {
        sendBuffer(this.label, this.buffer, this.size);
      }
    },
  });
}

function configureSymbols(symbols) {
  symbols.forEach((symbol) => {
    if (configuredSymbols.has(symbol)) {
      return;
    }
    hookSymbol(null, symbol, {
      onEnter(args) {
        this.buffer = args[0];
        this.size = args[1] ? args[1].toInt32() : 0x2000;
        this.label = symbol;
      },
      onLeave(retval) {
        if (this.buffer && this.size > 0) {
          sendBuffer(this.label, this.buffer, this.size);
        }
      },
    });
  });
}

rpc.exports = {
  configure(symbols) {
    configureSymbols(symbols || []);
  },
};

setImmediate(() => {
  installDefaultHooks();
  sendInfo('ready', { pid: Process.id });
});
