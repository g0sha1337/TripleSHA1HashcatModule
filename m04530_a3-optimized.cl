#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define HEX_LOWER_8_CONVERT_VECT(w, out0, out1) \
{ \
    u32x _w = (w); \
    u32x _h0 = ((_w >> 28) & 0xF); _h0 += (_h0 < 10) ? 0x30 : 0x57; \
    u32x _h1 = ((_w >> 24) & 0xF); _h1 += (_h1 < 10) ? 0x30 : 0x57; \
    u32x _h2 = ((_w >> 20) & 0xF); _h2 += (_h2 < 10) ? 0x30 : 0x57; \
    u32x _h3 = ((_w >> 16) & 0xF); _h3 += (_h3 < 10) ? 0x30 : 0x57; \
    u32x _h4 = ((_w >> 12) & 0xF); _h4 += (_h4 < 10) ? 0x30 : 0x57; \
    u32x _h5 = ((_w >>  8) & 0xF); _h5 += (_h5 < 10) ? 0x30 : 0x57; \
    u32x _h6 = ((_w >>  4) & 0xF); _h6 += (_h6 < 10) ? 0x30 : 0x57; \
    u32x _h7 = ((_w >>  0) & 0xF); _h7 += (_h7 < 10) ? 0x30 : 0x57; \
    out0 = _h0 | (_h1 << 8) | (_h2 << 16) | (_h3 << 24); \
    out1 = _h4 | (_h5 << 8) | (_h6 << 16) | (_h7 << 24); \
}

DECLSPEC void m04530_core_vect(
    const u32x *pw_buf, const u32 pw_len,
    const u32 *salt_buf, const u32 salt_len,
    u32x *r0, u32x *r1, u32x *r2, u32x *r3)
{
    sha1_ctx_vector_t ctx1;
    sha1_init_vector (&ctx1);
    sha1_update_vector_swap (&ctx1, pw_buf, pw_len);
    sha1_final_vector (&ctx1);

    u32x hex1[16] = { 0 };
    HEX_LOWER_8_CONVERT_VECT (ctx1.h[0], hex1[0], hex1[1]);
    HEX_LOWER_8_CONVERT_VECT (ctx1.h[1], hex1[2], hex1[3]);
    HEX_LOWER_8_CONVERT_VECT (ctx1.h[2], hex1[4], hex1[5]);
    HEX_LOWER_8_CONVERT_VECT (ctx1.h[3], hex1[6], hex1[7]);
    HEX_LOWER_8_CONVERT_VECT (ctx1.h[4], hex1[8], hex1[9]);

    u32x s[16] = { 0 };
    for (u32 i = 0; i < 16; i++) s[i] = salt_buf[i];

    sha1_ctx_vector_t ctx2;
    sha1_init_vector (&ctx2);
    sha1_update_vector_swap (&ctx2, s, salt_len);
    sha1_update_vector_swap (&ctx2, hex1, 40);
    sha1_final_vector (&ctx2);

    u32x hex2[16] = { 0 };
    HEX_LOWER_8_CONVERT_VECT (ctx2.h[0], hex2[0], hex2[1]);
    HEX_LOWER_8_CONVERT_VECT (ctx2.h[1], hex2[2], hex2[3]);
    HEX_LOWER_8_CONVERT_VECT (ctx2.h[2], hex2[4], hex2[5]);
    HEX_LOWER_8_CONVERT_VECT (ctx2.h[3], hex2[6], hex2[7]);
    HEX_LOWER_8_CONVERT_VECT (ctx2.h[4], hex2[8], hex2[9]);

    sha1_ctx_vector_t ctx3;
    sha1_init_vector (&ctx3);
    sha1_update_vector_swap (&ctx3, s, salt_len);
    sha1_update_vector_swap (&ctx3, hex2, 40);
    sha1_final_vector (&ctx3);

    *r0 = hc_swap32 (ctx3.h[0]);
    *r1 = hc_swap32 (ctx3.h[1]);
    *r2 = hc_swap32 (ctx3.h[2]);
    *r3 = hc_swap32 (ctx3.h[3]);
}

#define GEN_KERNEL_M(NAME) \
KERNEL_FQ KERNEL_FA void NAME (KERN_ATTR_VECTOR ()) \
{ \
    const u64 gid = get_global_id (0); \
    if (gid >= GID_CNT) return; \
    const u32 pw_len = pws[gid].pw_len; \
    const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len; \
    u32 s[16] = { 0 }; \
    for (u32 i = 0; i < 16; i++) s[i] = salt_bufs[SALT_POS_HOST].salt_buf[i]; \
    u32x pw_buf[16] = { 0 }; \
    for (u32 i = 0; i < 16; i++) pw_buf[i] = pws[gid].i[i]; \
    u32x w0l = pw_buf[0]; \
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE) \
    { \
        const u32x w0r = words_buf_r[il_pos / VECT_SIZE]; \
        pw_buf[0] = w0l | w0r; \
        u32x r0, r1, r2, r3; \
        m04530_core_vect(pw_buf, pw_len, s, salt_len, &r0, &r1, &r2, &r3); \
        COMPARE_M_SIMD (r0, r1, r2, r3); \
    } \
}

#define GEN_KERNEL_S(NAME) \
KERNEL_FQ KERNEL_FA void NAME (KERN_ATTR_VECTOR ()) \
{ \
    const u64 gid = get_global_id (0); \
    if (gid >= GID_CNT) return; \
    const u32 search[4] = { \
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0], \
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1], \
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2], \
        digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3] \
    }; \
    const u32 pw_len = pws[gid].pw_len; \
    const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len; \
    u32 s[16] = { 0 }; \
    for (u32 i = 0; i < 16; i++) s[i] = salt_bufs[SALT_POS_HOST].salt_buf[i]; \
    u32x pw_buf[16] = { 0 }; \
    for (u32 i = 0; i < 16; i++) pw_buf[i] = pws[gid].i[i]; \
    u32x w0l = pw_buf[0]; \
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE) \
    { \
        const u32x w0r = words_buf_r[il_pos / VECT_SIZE]; \
        pw_buf[0] = w0l | w0r; \
        u32x r0, r1, r2, r3; \
        m04530_core_vect(pw_buf, pw_len, s, salt_len, &r0, &r1, &r2, &r3); \
        COMPARE_S_SIMD (r0, r1, r2, r3); \
    } \
}

GEN_KERNEL_M(m04530_m04)
GEN_KERNEL_M(m04530_m08)
GEN_KERNEL_M(m04530_m16)
GEN_KERNEL_M(m04530_m32)

GEN_KERNEL_S(m04530_s04)
GEN_KERNEL_S(m04530_s08)
GEN_KERNEL_S(m04530_s16)
GEN_KERNEL_S(m04530_s32)