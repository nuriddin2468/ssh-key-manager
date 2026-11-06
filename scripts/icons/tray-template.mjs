// Draws src-tauri/icons/tray-template.png, the macOS menu bar icon: the app
// logo's keyhole and ring (assets/app-icon.svg) in black with alpha, which the
// menu bar tints. `node scripts/icons/tray-template.mjs <out.png> [px per unit]`.
import { writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';

const [, , out, scaleArg] = process.argv;
const PX = Number(scaleArg ?? 2); // pixels per unit
const X0 = 0,
  Y0 = 3.4,
  W = 24,
  H = 18; // the region drawn
const width = Math.round(W * PX),
  height = Math.round(H * PX);

function quad(p0, p1, p2, n = 12) {
  const pts = [];
  for (let i = 1; i <= n; i++) {
    const t = i / n,
      u = 1 - t;
    pts.push([
      u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
      u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1],
    ]);
  }
  return pts;
}
// M10.4 11.6 L9.1 18.4 Q8.9 19.7 10.2 19.7 H13.8 Q15.1 19.7 14.9 18.4 L13.6 11.6 Z
const body = [
  [10.4, 11.6],
  [9.1, 18.4],
  ...quad([9.1, 18.4], [8.9, 19.7], [10.2, 19.7]),
  [13.8, 19.7],
  ...quad([13.8, 19.7], [15.1, 19.7], [14.9, 18.4]),
  [13.6, 11.6],
];
function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i],
      [xj, yj] = poly[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
const inCircle = (x, y, cx, cy, r) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
const keyhole = (x, y) => inCircle(x, y, 12, 9.2, 4.1) || inPoly(x, y, body);
const hole = (x, y) => inCircle(x, y, 12, 9.2, 1.7);
const GAP = 0.85;
const near = (x, y) => {
  if (inCircle(x, y, 12, 9.2, 4.1 + GAP)) return true;
  for (let a = 0; a < 16; a++) {
    const t = (a / 16) * Math.PI * 2;
    if (inPoly(x + GAP * Math.cos(t), y + GAP * Math.sin(t), body)) return true;
  }
  return inPoly(x, y, body);
};
const ROT = (18 * Math.PI) / 180,
  RX = 10.4,
  RY = 3.8,
  STROKE = 1.15;
function ring(x, y) {
  const dx = x - 12,
    dy = y - 13.2;
  // Into the ellipse's frame (it is rotated by -18°).
  const ex = dx * Math.cos(ROT) - dy * Math.sin(ROT);
  const ey = dx * Math.sin(ROT) + dy * Math.cos(ROT);
  const f = (ex / RX) ** 2 + (ey / RY) ** 2 - 1;
  const g = Math.hypot((2 * ex) / RX ** 2, (2 * ey) / RY ** 2);
  return Math.abs(f) / g <= STROKE / 2;
}
const dot = (x, y) => inCircle(x, y, 20.6, 9.7, 1.35);
const shape = (x, y) => (keyhole(x, y) && !hole(x, y)) || (ring(x, y) && !near(x, y)) || dot(x, y);

const SS = 8;
const raw = Buffer.alloc((width * 4 + 1) * height);
for (let py = 0; py < height; py++) {
  raw[py * (width * 4 + 1)] = 0;
  for (let px = 0; px < width; px++) {
    let hits = 0;
    for (let sy = 0; sy < SS; sy++)
      for (let sx = 0; sx < SS; sx++)
        if (shape(X0 + (px + (sx + 0.5) / SS) / PX, Y0 + (py + (sy + 0.5) / SS) / PX)) hits++;
    const o = py * (width * 4 + 1) + 1 + px * 4;
    raw[o + 3] = Math.round((hits / (SS * SS)) * 255);
  }
}
const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const c = Buffer.alloc(4);
  c.writeUInt32BE(crc(td));
  return Buffer.concat([len, td, c]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(width, 0);
ihdr.writeUInt32BE(height, 4);
ihdr[8] = 8;
ihdr[9] = 6;
ihdr[10] = 0;
ihdr[11] = 0;
ihdr[12] = 0;
writeFileSync(
  out,
  Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]),
);
console.log(out, width, height);
