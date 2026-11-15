// The analysis engine, in a background worker.
//
// Pyodide and iamtrace run here, off the page's main thread, so the page keeps scrolling,
// typing and animating while a large account is analysed. The page sends
// { id, fn, args } and gets back { id, result } (the JSON string a web_api function returns)
// or { id, error }. The first message is { init: { pyodideUrl } }; when the engine is ready the
// worker answers { ready: { version, catalog, techniques } }, or { failed: message }.

let api = null;

async function boot(pyodideUrl) {
  const { loadPyodide } = await import(pyodideUrl + "pyodide.mjs");
  const pyodide = await loadPyodide({ indexURL: pyodideUrl });
  const fetchArchive = async (name) => {
    const resp = await fetch(new URL(name, self.location.href));
    return resp.ok ? await resp.arrayBuffer() : null;
  };
  const pkg = await fetchArchive("iamtrace.zip");
  if (!pkg) throw new Error("iamtrace.zip is missing from this site");
  pyodide.FS.mkdirTree("/home/pyodide/lib");
  pyodide.unpackArchive(pkg, "zip", { extractDir: "/home/pyodide/lib" });
  const catalog = await fetchArchive("catalog.zip");
  if (catalog) {
    pyodide.FS.mkdirTree("/home/pyodide/catalog");
    pyodide.unpackArchive(catalog, "zip", { extractDir: "/home/pyodide/catalog" });
  }
  pyodide.runPython("import sys; sys.path.insert(0, '/home/pyodide/lib')");
  api = pyodide.pyimport("iamtrace.web_api");
  const techniques = pyodide.runPython("from iamtrace.escalate import technique_catalog; len(technique_catalog())");
  return {
    version: String(pyodide.pyimport("iamtrace").__version__),
    catalog: JSON.parse(api.catalog_summary()),
    techniques: Number(techniques),
  };
}

self.onmessage = async (e) => {
  const msg = e.data || {};
  if (msg.init) {
    try {
      self.postMessage({ ready: await boot(msg.init.pyodideUrl) });
    } catch (err) {
      self.postMessage({ failed: String(err && err.message ? err.message : err) });
    }
    return;
  }
  const { id, fn, args } = msg;
  try {
    if (!api) throw new Error("the analysis engine is not ready");
    if (typeof api[fn] !== "function") throw new Error(`unknown engine function ${fn}`);
    const result = api[fn](...(args || []));
    self.postMessage({ id, result: String(result) });
  } catch (err) {
    self.postMessage({ id, error: String(err && err.message ? err.message : err) });
  }
};
