/*
 * Generic Frida script that intercepts common Lua bytecode loading APIs
 * and sends decoded buffers back to the Python host.
 */

const configuredSymbols = [];

function hookSymbol(symbol) {
  try {
    const addr = Module.findExportByName(null, symbol);
    if (!addr) {
      send({ type: 'log', level: 'debug', message: `symbol ${symbol} not found` });
      return;
    }
    Interceptor.attach(addr, {
      onEnter(args) {
        this.args = args;
      },
      onLeave(retval) {
        try {
          let bufPtr = this.args[1];
          let size = this.args[2].toInt32 ? this.args[2].toInt32() : this.args[2];
          if (!size || size > 4 * 1024 * 1024) {
            return;
          }
          const data = Memory.readByteArray(bufPtr, size);
          send({ type: 'buffer', symbol: symbol, size: size }, data);
        } catch (err) {
          send({ type: 'log', level: 'error', message: err.toString() });
        }
      }
    });
    send({ type: 'log', level: 'info', message: `hooked ${symbol}` });
  } catch (err) {
    send({ type: 'log', level: 'error', message: err.toString() });
  }
}

rpc.exports.configure = function(options) {
  const symbols = options.symbols || [
    'luaL_loadbuffer',
    'luaL_loadstring',
    'lua_load',
    'luaL_loadfilex'
  ];
  symbols.forEach(symbol => {
    if (configuredSymbols.indexOf(symbol) === -1) {
      configuredSymbols.push(symbol);
      hookSymbol(symbol);
    }
  });
};

rpc.exports.configure({});
