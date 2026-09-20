import { decode, encode, hasPngSignature } from 'fast-png';
import { badRequest } from './errors';

export const MAX_SKIN_BYTES = 128 * 1024;

/** Bound decompression before invoking a synchronous PNG decoder; discard all metadata. */
export async function sanitizeSkin(input: Uint8Array, model: 'default' | 'slim'): Promise<Uint8Array> {
  try {
    if (input.length > MAX_SKIN_BYTES || input.length < 45 || !hasPngSignature(input)) throw new Error();
    const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
    const kept: Uint8Array[] = [input.slice(0, 8)];
    const idat: Uint8Array[] = [];
    let width = 0, height = 0, depth = 0, channels = 0, ended = false;
    let seenIdat = false, idatEnded = false, seenPalette = false, seenTransparency = false;
    for (let offset = 8; offset < input.length;) {
      if (offset + 12 > input.length) throw new Error();
      const size = view.getUint32(offset);
      const end = offset + size + 12;
      if (end > input.length) throw new Error();
      const type = String.fromCharCode(...input.slice(offset + 4, offset + 8));
      if (offset === 8 && type !== 'IHDR') throw new Error();
      if (type === 'IHDR') {
        if (offset !== 8 || size !== 13) throw new Error();
        width = view.getUint32(offset + 8);
        height = view.getUint32(offset + 12);
        depth = input[offset + 16]!;
        const color = input[offset + 17]!;
        channels = ({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 } as Record<number, number>)[color] ?? 0;
        if (width !== 64 || ![32, 64].includes(height) || (height === 32 && model === 'slim')) throw new Error();
        if (!channels || ![1, 2, 4, 8].includes(depth) || (color !== 0 && color !== 3 && depth !== 8)) throw new Error();
        if (input[offset + 18] !== 0 || input[offset + 19] !== 0 || input[offset + 20] !== 0) throw new Error();
      } else if (type === 'IDAT') {
        if (idatEnded) throw new Error();
        seenIdat = true;
        idat.push(input.slice(offset + 8, end - 4));
      } else {
        if (seenIdat) idatEnded = true;
        if (type === 'PLTE') {
          if (seenPalette || seenIdat || size > 768 || !size || size % 3) throw new Error();
          seenPalette = true;
        } else if (type === 'tRNS') {
          if (seenTransparency || seenIdat || size > 256) throw new Error();
          seenTransparency = true;
        } else if (type === 'IEND') {
          if (size !== 0 || !seenIdat || end !== input.length) throw new Error();
          ended = true;
        } else if (type === 'acTL' || type[0] === type[0]?.toUpperCase()) throw new Error();
      }
      if (['IHDR', 'PLTE', 'tRNS', 'IDAT', 'IEND'].includes(type)) kept.push(input.slice(offset, end));
      offset = end;
    }
    if (!ended) throw new Error();
    const expected = height * (1 + Math.ceil(width * channels * depth / 8));
    const compressed = new Blob(idat);
    const reader = compressed.stream().pipeThrough(new DecompressionStream('deflate')).getReader();
    let inflated = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        inflated += next.value.length;
        if (inflated > expected) throw new Error();
      }
      if (inflated !== expected) throw new Error();
    } finally {
      await reader.cancel().catch(() => {});
    }
    const cleanInput = new Uint8Array(await new Blob(kept).arrayBuffer());
    const image = decode(cleanInput, { checkCrc: true });
    // Normalize to RGBA8, including palette/tRNS alpha, without carrying metadata.
    const rgba = new Uint8Array(width * height * 4);
    const mask = (1 << image.depth) - 1;
    for (let pixel = 0; pixel < width * height; pixel++) {
      const offset = pixel * image.channels;
      const sample = image.depth < 8
        ? (image.data[Math.floor(pixel * image.depth / 8)]! >> (8 - image.depth - (pixel * image.depth % 8))) & mask
        : image.data[offset]!;
      let r: number, g: number, b: number, a = 255;
      if (image.palette) {
        const color = image.palette[sample];
        if (!color) throw new Error();
        [r, g, b, a = 255] = color as [number, number, number, number?];
      } else if (image.channels <= 2) {
        r = g = b = Math.round(sample * 255 / mask);
        if (image.channels === 2) a = image.data[offset + 1]!;
        else if (image.transparency?.[0] === sample) a = 0;
      } else {
        r = sample; g = image.data[offset + 1]!; b = image.data[offset + 2]!;
        if (image.channels === 4) a = image.data[offset + 3]!;
        else if (image.transparency?.length === 3 && image.transparency[0] === r && image.transparency[1] === g && image.transparency[2] === b) a = 0;
      }
      rgba.set([r, g, b, a], pixel * 4);
    }
    return encode({ width, height, data: rgba, channels: 4, depth: 8 });
  } catch {
    throw badRequest('Invalid skin. Use a non-interlaced 8-bit (or indexed) PNG, 64×64 or 64×32, up to 128 KiB. Slim requires 64×64.');
  }
}
