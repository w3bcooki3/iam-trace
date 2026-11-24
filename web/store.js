// Saved data: what you load into iam-trace is kept in this browser's IndexedDB, so a refresh or a
// closed tab does not lose it. Nothing here touches the network.
//
// Two object stores:
//   data   one entry per kind of data, { value, savedAt, bytes }, under a short key ("account", ...)
//   trash  what was deleted, { label, entries: [{ key, value, savedAt, bytes }], deletedAt, bytes },
//          under an increasing number; restorable until it is emptied or 30 days pass.
// Moving entries to the trash is one transaction over both stores, so data is never in neither.

const DB_NAME = "iam-trace";
const DATA = "data";
const TRASH = "trash";
export const TRASH_DAYS = 30;
let dbPromise = null;

function openDb() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      if (!("indexedDB" in window)) return reject(new Error("this browser has no IndexedDB"));
      let req;
      try {
        req = indexedDB.open(DB_NAME, 2);
      } catch (e) {
        return reject(e); // some private modes throw instead of failing the request
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(DATA)) db.createObjectStore(DATA);
        if (!db.objectStoreNames.contains(TRASH)) db.createObjectStore(TRASH, { autoIncrement: true });
      };
      req.onsuccess = () => {
        const db = req.result;
        // Another tab opening a newer version asks this one to let go.
        db.onversionchange = () => { db.close(); dbPromise = null; };
        resolve(db);
      };
      req.onerror = () => reject(req.error || new Error("IndexedDB could not be opened"));
      req.onblocked = () => reject(new Error("IndexedDB is blocked by another tab of iam-trace; close it and reload"));
    });
    dbPromise.catch(() => { dbPromise = null; });
  }
  return dbPromise;
}

/** A quota error, under any of the names browsers use. */
export function isQuotaError(e) {
  return Boolean(e) && (e.name === "QuotaExceededError" || e.name === "NS_ERROR_DOM_QUOTA_REACHED" || e.code === 22 || /quota/i.test(e.message || ""));
}

function fail(tx, fallback) {
  const e = tx.error || new Error(fallback);
  if (isQuotaError(e)) {
    const q = new Error("this browser's storage for the site is full");
    q.name = "QuotaExceededError";
    return q;
  }
  return e;
}

async function run(stores, mode, work) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    let tx;
    try {
      tx = db.transaction(stores, mode);
    } catch (e) {
      return reject(e);
    }
    let result;
    try {
      result = work(tx);
    } catch (e) {
      try { tx.abort(); } catch { /* already finished */ }
      return reject(e);
    }
    tx.oncomplete = () => resolve(result && "result" in result ? result.result : result);
    tx.onerror = () => reject(fail(tx, "the browser refused to save"));
    tx.onabort = () => reject(fail(tx, "the browser refused to save (storage may be full)"));
  });
}

function cursorAll(store, map) {
  return new Promise((resolve, reject) => {
    const out = [];
    const req = store.openCursor();
    req.onsuccess = () => {
      const c = req.result;
      if (!c) return resolve(out);
      out.push(map(c));
      c.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

export const size = (value) => new Blob([JSON.stringify(value) ?? ""]).size;
const entry = (value) => ({ value, savedAt: Date.now(), bytes: size(value) });

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
    return run(DATA, "readwrite", (tx) => { tx.objectStore(DATA).put(entry(value), key); });
  },
  async get(key) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const req = db.transaction(DATA, "readonly").objectStore(DATA).get(key);
      req.onsuccess = () => resolve(req.result ? req.result.value : undefined);
      req.onerror = () => reject(req.error);
    });
  },
  /** Deletes for good, without the trash (used when a value becomes empty). */
  async del(key) {
    return run(DATA, "readwrite", (tx) => { tx.objectStore(DATA).delete(key); });
  },
  /** Deletes all saved data and the trash, for good. */
  async clear() {
    return run([DATA, TRASH], "readwrite", (tx) => { tx.objectStore(DATA).clear(); tx.objectStore(TRASH).clear(); });
  },
  /** Every entry as { key, value, savedAt, bytes }. */
  async all() {
    const db = await openDb();
    const tx = db.transaction(DATA, "readonly");
    return cursorAll(tx.objectStore(DATA), (c) => ({ key: c.key, ...c.value }));
  },

  // --- trash ---------------------------------------------------------------------------------

  /** Moves the saved entries under `keys` into one trash item. Returns its id, or null if none of
   * the keys had saved data. `extra` adds entries that were never saved (saving off). */
  async trash(keys, label, extra = []) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([DATA, TRASH], "readwrite");
      const data = tx.objectStore(DATA);
      const found = [];
      let id = null;
      let pending = keys.length;
      const finish = () => {
        const seen = new Set(found.map((e) => e.key));
        const entries = [...found, ...extra.filter((e) => !seen.has(e.key)).map((e) => ({ key: e.key, ...entry(e.value) }))];
        if (!entries.length) return;
        for (const e of found) data.delete(e.key);
        const req = tx.objectStore(TRASH).add({ label, entries, deletedAt: Date.now(), bytes: entries.reduce((n, e) => n + (e.bytes || 0), 0) });
        req.onsuccess = () => { id = req.result; };
      };
      if (!pending) finish();
      for (const k of keys) {
        const req = data.get(k);
        req.onsuccess = () => {
          if (req.result) found.push({ key: k, ...req.result });
          if (--pending === 0) finish();
        };
      }
      tx.oncomplete = () => resolve(id);
      tx.onerror = () => reject(fail(tx, "the browser refused to move the data to the trash"));
      tx.onabort = () => reject(fail(tx, "the browser refused to move the data to the trash"));
    });
  },
  /** Every trash item as { id, label, entries, deletedAt, bytes }, newest first. */
  async trashList() {
    const db = await openDb();
    const tx = db.transaction(TRASH, "readonly");
    const items = await cursorAll(tx.objectStore(TRASH), (c) => ({ id: c.key, ...c.value }));
    return items.sort((a, b) => b.deletedAt - a.deletedAt);
  },
  /** Puts a trash item's entries back as saved data and removes it from the trash. Saved data
   * under the same keys is moved to the trash first (labelled `replacedLabel`), so nothing is lost. */
  async restore(id, replacedLabel) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([DATA, TRASH], "readwrite");
      const data = tx.objectStore(DATA);
      const trash = tx.objectStore(TRASH);
      let item = null;
      const get = trash.get(id);
      get.onsuccess = () => {
        item = get.result;
        if (!item) return;
        const replaced = [];
        let pending = item.entries.length;
        const put = () => {
          if (replaced.length) {
            trash.add({ label: replacedLabel, entries: replaced, deletedAt: Date.now(), bytes: replaced.reduce((n, e) => n + (e.bytes || 0), 0) });
          }
          for (const e of item.entries) data.put({ value: e.value, savedAt: e.savedAt || Date.now(), bytes: e.bytes || size(e.value) }, e.key);
          trash.delete(id);
        };
        if (!pending) return put();
        for (const e of item.entries) {
          const cur = data.get(e.key);
          cur.onsuccess = () => {
            if (cur.result && JSON.stringify(cur.result.value) !== JSON.stringify(e.value)) replaced.push({ key: e.key, ...cur.result });
            if (--pending === 0) put();
          };
        }
      };
      tx.oncomplete = () => resolve(item ? item.entries : null);
      tx.onerror = () => reject(fail(tx, "the browser refused to restore the data"));
      tx.onabort = () => reject(fail(tx, "the browser refused to restore the data"));
    });
  },
  async trashDelete(id) {
    return run(TRASH, "readwrite", (tx) => { tx.objectStore(TRASH).delete(id); });
  },
  async trashEmpty() {
    return run(TRASH, "readwrite", (tx) => { tx.objectStore(TRASH).clear(); });
  },
  /** Deletes trash items older than TRASH_DAYS. Returns how many. */
  async trashPurge(now = Date.now()) {
    const old = (await this.trashList()).filter((t) => now - t.deletedAt > TRASH_DAYS * 86400000);
    if (old.length) await run(TRASH, "readwrite", (tx) => { for (const t of old) tx.objectStore(TRASH).delete(t.id); });
    return old.length;
  },
};

// --- how much space there is ----------------------------------------------------------------------

/** { usage, quota, free, persisted, supported } for this site, from the Storage API. Browsers
 * estimate (and may round or pad) these numbers; `supported` is false where there is no API. */
export async function storageInfo() {
  const s = navigator.storage;
  if (!s || typeof s.estimate !== "function") return { supported: false, persisted: false };
  try {
    const { usage = 0, quota = 0 } = await s.estimate();
    const persisted = typeof s.persisted === "function" ? await s.persisted() : false;
    return { supported: quota > 0, usage, quota, free: Math.max(0, quota - usage), persisted };
  } catch {
    return { supported: false, persisted: false };
  }
}

/** Asks the browser not to clear this site's storage when the disk is low. Chrome and Edge decide
 * by themselves; Firefox asks the user. Returns whether storage is now persistent. */
export async function askPersist() {
  try {
    return Boolean(await navigator.storage?.persist?.());
  } catch {
    return false;
  }
}

/** Below this much free space, or this share of the quota, the app warns. */
export const LOW_FREE_BYTES = 50 * 1024 * 1024;
export const LOW_FREE_SHARE = 0.1;
export function isLow(info) {
  return Boolean(info?.supported) && (info.free < LOW_FREE_BYTES || info.free < info.quota * LOW_FREE_SHARE);
}
