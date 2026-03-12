#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define HEX_LOWER_8_CONVERT(w, out0, out1) \
{ \
  u32 _w = (w); \
  u32 _h0 = ((_w >> 28) & 0xF); _h0 += (_h0 < 10) ? 0x30 : 0x57; \
  u32 _h1 = ((_w >> 24) & 0xF); _h1 += (_h1 < 10) ? 0x30 : 0x57; \
  u32 _h2 = ((_w >> 20) & 0xF); _h2 += (_h2 < 10) ? 0x30 : 0x57; \
  u32 _h3 = ((_w >> 16) & 0xF); _h3 += (_h3 < 10) ? 0x30 : 0x57; \
  u32 _h4 = ((_w >> 12) & 0xF); _h4 += (_h4 < 10) ? 0x30 : 0x57; \
  u32 _h5 = ((_w >>  8) & 0xF); _h5 += (_h5 < 10) ? 0x30 : 0x57; \
  u32 _h6 = ((_w >>  4) & 0xF); _h6 += (_h6 < 10) ? 0x30 : 0x57; \
  u32 _h7 = ((_w >>  0) & 0xF); _h7 += (_h7 < 10) ? 0x30 : 0x57; \
  out0 = _h0 | (_h1 << 8) | (_h2 << 16) | (_h3 << 24); \
  out1 = _h4 | (_h5 << 8) | (_h6 << 16) | (_h7 << 24); \
}

DECLSPEC void m04530_core (const u64 gid,
                           GLOBAL_AS const pw_t *pws,
                           GLOBAL_AS const salt_t *salt_bufs,
                           GLOBAL_AS const kernel_param_t *kernel_param,
                           PRIVATE_AS u32 *r0,
                           PRIVATE_AS u32 *r1,
                           PRIVATE_AS u32 *r2,
                           PRIVATE_AS u32 *r3,
                           PRIVATE_AS u32 *r4)
{
  const u32 pw_len = pws[gid].pw_len;
  u32 pw_buf[16];
  for (int i = 0; i < 16; i++) pw_buf[i] = pws[gid].i[i];

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;
  u32 salt_buf[16];
  for (int i = 0; i < 16; i++) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  /** Step 1: sha1($pass) */
  sha1_ctx_t ctx1;
  sha1_init (&ctx1);
  sha1_update_swap (&ctx1, pw_buf, pw_len);
  sha1_final (&ctx1);

  u32 hex1[16] = { 0 };
  HEX_LOWER_8_CONVERT (ctx1.h[0], hex1[0], hex1[1]);
  HEX_LOWER_8_CONVERT (ctx1.h[1], hex1[2], hex1[3]);
  HEX_LOWER_8_CONVERT (ctx1.h[2], hex1[4], hex1[5]);
  HEX_LOWER_8_CONVERT (ctx1.h[3], hex1[6], hex1[7]);
  HEX_LOWER_8_CONVERT (ctx1.h[4], hex1[8], hex1[9]);

  /** Step 2: sha1($salt . hex1) */
  sha1_ctx_t ctx2;
  sha1_init (&ctx2);
  sha1_update_swap (&ctx2, salt_buf, salt_len);
  sha1_update_swap (&ctx2, hex1, 40);
  sha1_final (&ctx2);

  u32 hex2[16] = { 0 };
  HEX_LOWER_8_CONVERT (ctx2.h[0], hex2[0], hex2[1]);
  HEX_LOWER_8_CONVERT (ctx2.h[1], hex2[2], hex2[3]);
  HEX_LOWER_8_CONVERT (ctx2.h[2], hex2[4], hex2[5]);
  HEX_LOWER_8_CONVERT (ctx2.h[3], hex2[6], hex2[7]);
  HEX_LOWER_8_CONVERT (ctx2.h[4], hex2[8], hex2[9]);

  /** Step 3: sha1($salt . hex2) */
  sha1_ctx_t ctx3;
  sha1_init (&ctx3);
  sha1_update_swap (&ctx3, salt_buf, salt_len);
  sha1_update_swap (&ctx3, hex2, 40);
  sha1_final (&ctx3);

  *r0 = hc_swap32_S (ctx3.h[0]);
  *r1 = hc_swap32_S (ctx3.h[1]);
  *r2 = hc_swap32_S (ctx3.h[2]);
  *r3 = hc_swap32_S (ctx3.h[3]);
  *r4 = hc_swap32_S (ctx3.h[4]);
}

KERNEL_FQ void m04530_mxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 il_pos = 0;

  u32 r0, r1, r2, r3, r4;
  m04530_core (gid, pws, salt_bufs, kernel_param, &r0, &r1, &r2, &r3, &r4);

  COMPARE_M_SCALAR (r0, r1, r2, r3);
}

KERNEL_FQ void m04530_sxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 il_pos = 0;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  u32 r0, r1, r2, r3, r4;
  m04530_core (gid, pws, salt_bufs, kernel_param, &r0, &r1, &r2, &r3, &r4);

  COMPARE_S_SCALAR (r0, r1, r2, r3);
}