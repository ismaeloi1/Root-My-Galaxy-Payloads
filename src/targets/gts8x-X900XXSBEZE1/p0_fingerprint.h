/*
 * P0 fingerprint table for SM-X900 / X900XXSBEZE1
 *
 * This table must be generated from the actual kernel binary:
 *   1. Extract boot.img from firmware X900XXSBEZE1
 *   2. Decompress kernel Image (lz4 or gzip)
 *   3. For each slide candidate (0x000000..0x1f0000, step 0x10000),
 *      read 8 qwords at probe offsets from the kernel Image
 *   4. Use tools/generate_p0_fingerprint.pl or manual extraction
 *
 * Until extracted, this file contains an empty table that will cause
 * the P0 oracle to fail at runtime — the exploit will fall back to
 * brute-force slide if available.
 */

#define P0_FINGERPRINT_WORDS 8

static const uintptr_t p0_fingerprint_offsets[P0_FINGERPRINT_WORDS] = {
  0x000, 0x200, 0x400, 0x600, 0x800, 0xa00, 0xc00, 0xe00
};

struct p0_fingerprint {
  uintptr_t slide;
  uint64_t words[P0_FINGERPRINT_WORDS];
};

/* EXTRACT: Generate from kernel Image binary.
 * Each row = { slide_value, { qword@0x000, qword@0x200, ..., qword@0xe00 } }
 * Run: tools/generate_p0_fingerprint.pl <kernel_Image> <base_offset>
 */
static const struct p0_fingerprint p0_fingerprints[] = {
  { 0x000000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x010000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x020000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x030000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x040000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x050000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x060000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x070000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x080000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x090000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0a0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0b0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0c0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0d0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0e0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0f0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x100000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x110000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x120000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x130000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x140000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x150000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x160000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x170000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x180000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x190000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1a0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1b0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1c0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1d0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1e0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1f0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
};
