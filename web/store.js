// Saved data: what you load into iam-trace is kept in this browser's IndexedDB, so a refresh or a
// closed tab does not lose it. Nothing here touches the network. Each entry is
// { value, savedAt, bytes } under a short key ("account", "diff", ...).

const DB_NAME = "iam-trace";
const STORE = "data";
let dbPromise = null;

function openDb() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      if (!("indexedDB" in window)) return reject(new Error("this browser has no IndexedDB"));
      let req;
      try {
        req = indexedDB.open(DB_NAME, 1);
      } catch (e) {
        return reject(e); // some private modes throw instead of failing the request
      }
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error("IndexedDB could not be opened"));
      req.onblocked = () => reject(new Error("IndexedDB is blocked by another tab"));
    });
    dbPromise.catch(() => { dbPromise = null; });
  }
  return dbPromise;
}

async function run(mode, work) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = work(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(req ? req.result : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("the browser refused to save (storage may be full)"));
  });
}

const size = (value) => new Blob([JSON.stringify(value)]).size;

export const store = {
  /** True if IndexedDB opens in this browser. */
  async available() {
    try {
      await openDb();
      return true;
    } catch {
      return false;
    }
  },
  async set(key, value) {
    return run("readwrite", (s) => s.put({ value, savedAt: Date.now(), bytes: size(value) }, key));
  },
  async get(key) {
    const entry = await run("readonly", (s) => s.get(key));
    return entry ? entry.value : undefined;
  },
  async del(key) {
    return run("readwrite", (s) => s.delete(key));
  },
  async clear() {
    return run("readwrite", (s) => s.clear());
  },
  /** Every entry as { key, value, savedAt, bytes }. */
  async all() {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const out = [];
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).openCursor();
      req.onsuccess = () => {
        const c = req.result;
        if (!c) return;
        out.push({ key: c.key, ...c.value });
        c.continue();
      };
      tx.oncomplete = () => resolve(out);
      tx.onerror = () => reject(tx.error);
    });
  },
};
