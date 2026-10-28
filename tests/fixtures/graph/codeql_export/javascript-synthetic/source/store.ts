import * as fs from "fs";

interface Store {
  save(key: string): void;
}

class MemoryStore implements Store {
  last = "";

  save(key: string): void {
    this.last = key;
  }
}

class FileStore implements Store {
  save(key: string): void {
    fs.writeFileSync(key, "");
  }
}

export function persist(durable: boolean, key: string): void {
  const s: Store = durable ? new FileStore() : new MemoryStore();
  s.save(key);
}

export function invoke(obj: any, name: string): void {
  obj[name]();
}
