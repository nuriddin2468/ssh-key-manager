// Packs extension/dist/chromium (run build.mjs first) into the zip uploaded
// to the Chrome Web Store: extension/dist/ssh-key-manager-chromium-<version>.zip.
// The store keeps the item's key itself, so the manifest's `key` is left out:
// it is the item's public key, there so unpacked builds get the store's id.
// Entries are sorted and dated 1980-01-01, so the same build always gives the
// same zip.

import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';

const root = dirname(fileURLToPath(import.meta.url));
const build = join(root, 'dist', 'chromium');

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** A zip of `files` ([name, bytes] pairs), deflated, with no timestamps. */
function zip(files) {
  const DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, data] of files) {
    const path = Buffer.from(name, 'utf8');
    const packed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4); // version needed: 2.0
    head.writeUInt16LE(0x0800, 6); // names are UTF-8
    head.writeUInt16LE(8, 8); // deflate
    head.writeUInt16LE(0, 10);
    head.writeUInt16LE(DOS_DATE, 12);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(packed.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(path.length, 26);
    head.writeUInt16LE(0, 28);
    local.push(head, path, packed);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix, 2.0
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(0x0800, 8);
    entry.writeUInt16LE(8, 10);
    entry.writeUInt16LE(0, 12);
    entry.writeUInt16LE(DOS_DATE, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(packed.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(path.length, 28);
    entry.writeUInt32LE((0o100644 << 16) >>> 0, 38); // a regular file, rw-r--r--
    entry.writeUInt32LE(offset, 42);
    central.push(entry, path);
    offset += head.length + path.length + packed.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

const files = [];
for (const entry of await readdir(build, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile() || entry.name.startsWith('.')) continue;
  const path = join(entry.parentPath, entry.name);
  files.push([relative(build, path).split(sep).join('/'), await readFile(path)]);
}
files.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

const at = files.findIndex(([name]) => name === 'manifest.json');
if (at < 0) throw new Error('extension/dist/chromium has no manifest.json: run build.mjs first');
const manifest = JSON.parse(files[at][1].toString('utf8'));
delete manifest.key;
files[at][1] = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);

const name = `ssh-key-manager-chromium-${manifest.version}.zip`;
await writeFile(join(root, 'dist', name), zip(files));
console.log(`extension/dist/${name} (${files.length} files)`);
