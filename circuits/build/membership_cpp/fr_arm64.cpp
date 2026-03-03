/**
 * fr_arm64.cpp - BN254 field arithmetic for ARM64
 * 
 * This file provides the high-level Fr_* functions that membership.cpp needs.
 * The low-level Fr_raw* functions come from fr_raw_arm64.s (ARM64 assembly).
 * 
 * Build with: fr_arm64.cpp + fr_raw_arm64.s + fr_helpers.cpp (for div/mod/pow)
 */

#include "fr.hpp"
#include <cstring>
#include <cassert>
#include <gmp.h>

// ============================================================================
// Constants (defined in fr_raw_arm64.s as Fr_rawq)
// ============================================================================

// BN254 scalar field modulus q
static const uint64_t Fr_rawq_local[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
};

// R^2 mod q (for Montgomery conversion)
static const uint64_t Fr_rawR2[4] = {
    0x1bb8e645ae216da7ULL,
    0x53fe3ab1e35c59e3ULL,
    0x8c49833d53bb8085ULL,
    0x0216d0b17f4e44a5ULL
};

// R^3 mod q
static const uint64_t Fr_rawR3_local[4] = {
    0x5e94d8e1b4bf0040ULL,
    0x2a489cbe1cfbb6b8ULL,
    0x893cc664a19fcfedULL,
    0x0cf8594b7fcc657cULL
};

// (q-1)/2 for comparison
static const uint64_t Fr_half[4] = {
    0xa1f0fac9f8000000ULL,
    0x9419f4243cdcb848ULL,
    0xdc2822db40c0ac2eULL,
    0x183227397098d014ULL
};

// Global constants
FrElement Fr_q = { 0, Fr_LONG, { Fr_rawq_local[0], Fr_rawq_local[1], Fr_rawq_local[2], Fr_rawq_local[3] } };
FrElement Fr_R3 = { 0, Fr_LONGMONTGOMERY, { Fr_rawR3_local[0], Fr_rawR3_local[1], Fr_rawR3_local[2], Fr_rawR3_local[3] } };
FrRawElement Fr_rawq = { Fr_rawq_local[0], Fr_rawq_local[1], Fr_rawq_local[2], Fr_rawq_local[3] };
FrRawElement Fr_rawR3 = { Fr_rawR3_local[0], Fr_rawR3_local[1], Fr_rawR3_local[2], Fr_rawR3_local[3] };

// ============================================================================
// External declarations for ARM64 assembly functions (from fr_raw_arm64.s)
// ============================================================================

extern "C" {
    void Fr_rawCopy(FrRawElement r, const FrRawElement a);
    void Fr_rawSwap(FrRawElement a, FrRawElement b);
    void Fr_rawAdd(FrRawElement r, const FrRawElement a, const FrRawElement b);
    void Fr_rawSub(FrRawElement r, const FrRawElement a, const FrRawElement b);
    void Fr_rawNeg(FrRawElement r, const FrRawElement a);
    void Fr_rawMMul(FrRawElement r, const FrRawElement a, const FrRawElement b);
    void Fr_rawMMul1(FrRawElement r, const FrRawElement a, uint64_t b);
    void Fr_rawFromMontgomery(FrRawElement r, const FrRawElement a);
    int Fr_rawIsEq(const FrRawElement a, const FrRawElement b);
    int Fr_rawIsZero(const FrRawElement a);
    void Fr_rawCopyS2L(FrRawElement r, int64_t v);
    int Fr_rawCmp(const FrRawElement a, const FrRawElement b);
    void Fr_rawAnd(FrRawElement r, const FrRawElement a, const FrRawElement b);
    void Fr_rawOr(FrRawElement r, const FrRawElement a, const FrRawElement b);
    void Fr_rawXor(FrRawElement r, const FrRawElement a, const FrRawElement b);
    void Fr_rawShr(FrRawElement r, const FrRawElement a, uint64_t b);
    void Fr_rawShl(FrRawElement r, const FrRawElement a, uint64_t b);
    void Fr_rawNot(FrRawElement r, const FrRawElement a);
}

// ============================================================================
// Helper functions
// ============================================================================

static inline bool raw_isZero(const FrRawElement a) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

static inline int raw_cmp(const FrRawElement a, const FrRawElement b) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static void Fr_toLongNormalInternal(FrElement *r, const FrElement *a) {
    if (a->type & Fr_LONG) {
        if (a->type == Fr_LONGMONTGOMERY) {
            Fr_rawFromMontgomery(r->longVal, a->longVal);
        } else {
            Fr_rawCopy(r->longVal, a->longVal);
        }
    } else {
        if (a->shortVal < 0) {
            r->longVal[0] = -((int64_t)a->shortVal);
            r->longVal[1] = r->longVal[2] = r->longVal[3] = 0;
            Fr_rawNeg(r->longVal, r->longVal);
        } else {
            r->longVal[0] = a->shortVal;
            r->longVal[1] = r->longVal[2] = r->longVal[3] = 0;
        }
    }
    r->type = Fr_LONG;
    r->shortVal = 0;
}

// ============================================================================
// Basic operations
// ============================================================================

extern "C" void Fr_copy(PFrElement r, PFrElement a) {
    *r = *a;
}

extern "C" void Fr_copyn(PFrElement r, PFrElement a, int n) {
    memcpy(r, a, n * sizeof(FrElement));
}

extern "C" void Fr_toNormal(PFrElement r, PFrElement a) {
    if (!(a->type & Fr_LONG)) {
        *r = *a;
        return;
    }
    if (a->type == Fr_LONGMONTGOMERY) {
        Fr_rawFromMontgomery(r->longVal, a->longVal);
    } else {
        Fr_rawCopy(r->longVal, a->longVal);
    }
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_toLongNormal(PFrElement r, PFrElement a) {
    Fr_toLongNormalInternal(r, a);
}

static void Fr_toMontgomeryInternal(FrElement *r, const FrElement *a) {
    if (a->type == Fr_LONGMONTGOMERY) {
        *r = *a;
        return;
    }
    FrElement tmp;
    Fr_toLongNormalInternal(&tmp, a);
    // r = tmp * R^2 * R^-1 = tmp * R (mod q)
    Fr_rawMMul(r->longVal, tmp.longVal, Fr_rawR3);
    Fr_rawMMul(r->longVal, r->longVal, Fr_rawR3);  // Double to get R^2 factor
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_toMontgomery(PFrElement r, PFrElement a) {
    Fr_toMontgomeryInternal(r, a);
}

// ============================================================================
// Arithmetic operations
// ============================================================================

extern "C" void Fr_add(PFrElement r, PFrElement a, PFrElement b) {
    if (!(a->type & Fr_LONG) && !(b->type & Fr_LONG)) {
        int64_t sum = (int64_t)a->shortVal + (int64_t)b->shortVal;
        if (sum >= -0x80000000LL && sum < 0x80000000LL) {
            r->type = Fr_SHORT;
            r->shortVal = (int32_t)sum;
            return;
        }
    }
    FrElement ma, mb;
    Fr_toMontgomeryInternal(&ma, a);
    Fr_toMontgomeryInternal(&mb, b);
    Fr_rawAdd(r->longVal, ma.longVal, mb.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_sub(PFrElement r, PFrElement a, PFrElement b) {
    if (!(a->type & Fr_LONG) && !(b->type & Fr_LONG)) {
        int64_t diff = (int64_t)a->shortVal - (int64_t)b->shortVal;
        if (diff >= -0x80000000LL && diff < 0x80000000LL) {
            r->type = Fr_SHORT;
            r->shortVal = (int32_t)diff;
            return;
        }
    }
    FrElement ma, mb;
    Fr_toMontgomeryInternal(&ma, a);
    Fr_toMontgomeryInternal(&mb, b);
    Fr_rawSub(r->longVal, ma.longVal, mb.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_neg(PFrElement r, PFrElement a) {
    if (!(a->type & Fr_LONG)) {
        if (a->shortVal == (int32_t)0x80000000) {
            r->longVal[0] = 0x80000000ULL;
            r->longVal[1] = r->longVal[2] = r->longVal[3] = 0;
            r->type = Fr_LONG;
            r->shortVal = 0;
        } else {
            r->type = Fr_SHORT;
            r->shortVal = -a->shortVal;
        }
        return;
    }
    FrElement ma;
    Fr_toMontgomeryInternal(&ma, a);
    Fr_rawNeg(r->longVal, ma.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_mul(PFrElement r, PFrElement a, PFrElement b) {
    FrElement ma, mb;
    Fr_toMontgomeryInternal(&ma, a);
    Fr_toMontgomeryInternal(&mb, b);
    Fr_rawMMul(r->longVal, ma.longVal, mb.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_square(PFrElement r, PFrElement a) {
    Fr_mul(r, a, a);
}

// ============================================================================
// Comparison operations (CRITICAL: uses signed semantics for SHORT values)
// ============================================================================

static int Fr_IsNegative(const FrRawElement a) {
    return raw_cmp(a, Fr_half) > 0;
}

static int Fr_cmp(PFrElement a, PFrElement b) {
    // Both SHORT: simple signed comparison
    if (!(a->type & Fr_LONG) && !(b->type & Fr_LONG)) {
        if (a->shortVal < b->shortVal) return -1;
        if (a->shortVal > b->shortVal) return 1;
        return 0;
    }
    
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    
    int a_neg = Fr_IsNegative(na.longVal);
    int b_neg = Fr_IsNegative(nb.longVal);
    
    if (a_neg && !b_neg) return -1;
    if (!a_neg && b_neg) return 1;
    
    int cmp = raw_cmp(na.longVal, nb.longVal);
    return a_neg ? -cmp : cmp;
}

extern "C" void Fr_lt(PFrElement r, PFrElement a, PFrElement b) {
    r->type = Fr_SHORT;
    r->shortVal = (Fr_cmp(a, b) < 0) ? 1 : 0;
}

extern "C" void Fr_gt(PFrElement r, PFrElement a, PFrElement b) {
    r->type = Fr_SHORT;
    r->shortVal = (Fr_cmp(a, b) > 0) ? 1 : 0;
}

extern "C" void Fr_leq(PFrElement r, PFrElement a, PFrElement b) {
    r->type = Fr_SHORT;
    r->shortVal = (Fr_cmp(a, b) <= 0) ? 1 : 0;
}

extern "C" void Fr_geq(PFrElement r, PFrElement a, PFrElement b) {
    r->type = Fr_SHORT;
    r->shortVal = (Fr_cmp(a, b) >= 0) ? 1 : 0;
}

extern "C" void Fr_eq(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->type = Fr_SHORT;
    r->shortVal = (raw_cmp(na.longVal, nb.longVal) == 0) ? 1 : 0;
}

extern "C" void Fr_neq(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->type = Fr_SHORT;
    r->shortVal = (raw_cmp(na.longVal, nb.longVal) != 0) ? 1 : 0;
}

extern "C" int Fr_isTrue(PFrElement a) {
    FrElement tmp;
    Fr_toNormal(&tmp, a);
    if (tmp.type & Fr_LONG) {
        return !raw_isZero(tmp.longVal);
    }
    return tmp.shortVal != 0;
}

extern "C" int Fr_toInt(PFrElement a) {
    FrElement tmp;
    Fr_toNormal(&tmp, a);
    if (tmp.type & Fr_LONG) {
        if (tmp.longVal[1] == 0 && tmp.longVal[2] == 0 && tmp.longVal[3] == 0) {
            if (tmp.longVal[0] <= 0x7FFFFFFF) {
                return (int32_t)tmp.longVal[0];
            }
        }
        // Check if negative (close to q)
        if (Fr_IsNegative(tmp.longVal)) {
            FrRawElement neg;
            Fr_rawSub(neg, Fr_rawq, tmp.longVal);
            if (neg[1] == 0 && neg[2] == 0 && neg[3] == 0 && neg[0] <= 0x80000000ULL) {
                return -(int32_t)neg[0];
            }
        }
        return 0;
    }
    return tmp.shortVal;
}

// ============================================================================
// Logical operations
// ============================================================================

extern "C" void Fr_land(PFrElement r, PFrElement a, PFrElement b) {
    r->type = Fr_SHORT;
    r->shortVal = (Fr_isTrue(a) && Fr_isTrue(b)) ? 1 : 0;
}

extern "C" void Fr_lor(PFrElement r, PFrElement a, PFrElement b) {
    r->type = Fr_SHORT;
    r->shortVal = (Fr_isTrue(a) || Fr_isTrue(b)) ? 1 : 0;
}

extern "C" void Fr_lnot(PFrElement r, PFrElement a) {
    r->type = Fr_SHORT;
    r->shortVal = Fr_isTrue(a) ? 0 : 1;
}

// ============================================================================
// Bitwise operations
// ============================================================================

extern "C" void Fr_band(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    Fr_rawAnd(r->longVal, na.longVal, nb.longVal);
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_bor(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    Fr_rawOr(r->longVal, na.longVal, nb.longVal);
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_bxor(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    Fr_rawXor(r->longVal, na.longVal, nb.longVal);
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_bnot(PFrElement r, PFrElement a) {
    FrElement na;
    Fr_toLongNormalInternal(&na, a);
    Fr_rawNot(r->longVal, na.longVal);
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_shl(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na;
    Fr_toLongNormalInternal(&na, a);
    uint64_t shift = (b->type & Fr_LONG) ? b->longVal[0] : (uint64_t)b->shortVal;
    Fr_rawShl(r->longVal, na.longVal, shift);
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_shr(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na;
    Fr_toLongNormalInternal(&na, a);
    uint64_t shift = (b->type & Fr_LONG) ? b->longVal[0] : (uint64_t)b->shortVal;
    Fr_rawShr(r->longVal, na.longVal, shift);
    r->type = Fr_LONG;
    r->shortVal = 0;
}

// ============================================================================
// Division operations (use GMP)
// ============================================================================

static void Fr_toMpz(mpz_t r, PFrElement a) {
    FrElement tmp;
    Fr_toLongNormalInternal(&tmp, a);
    mpz_import(r, 4, -1, 8, -1, 0, tmp.longVal);
}

static void Fr_fromMpz(PFrElement r, mpz_t v) {
    mpz_t q;
    mpz_init(q);
    mpz_import(q, 4, -1, 8, -1, 0, Fr_rawq);
    mpz_mod(v, v, q);
    
    size_t count = 0;
    mpz_export(r->longVal, &count, -1, 8, -1, 0, v);
    for (size_t i = count; i < 4; i++) {
        r->longVal[i] = 0;
    }
    r->type = Fr_LONG;
    r->shortVal = 0;
    mpz_clear(q);
}

extern "C" void Fr_idiv(PFrElement r, PFrElement a, PFrElement b) {
    mpz_t ma, mb, mr;
    mpz_init(ma); mpz_init(mb); mpz_init(mr);
    Fr_toMpz(ma, a);
    Fr_toMpz(mb, b);
    mpz_tdiv_q(mr, ma, mb);
    Fr_fromMpz(r, mr);
    mpz_clear(ma); mpz_clear(mb); mpz_clear(mr);
}

extern "C" void Fr_mod(PFrElement r, PFrElement a, PFrElement b) {
    mpz_t ma, mb, mr;
    mpz_init(ma); mpz_init(mb); mpz_init(mr);
    Fr_toMpz(ma, a);
    Fr_toMpz(mb, b);
    mpz_tdiv_r(mr, ma, mb);
    Fr_fromMpz(r, mr);
    mpz_clear(ma); mpz_clear(mb); mpz_clear(mr);
}

extern "C" void Fr_inv(PFrElement r, PFrElement a) {
    mpz_t ma, mr, q;
    mpz_init(ma); mpz_init(mr); mpz_init(q);
    Fr_toMpz(ma, a);
    mpz_import(q, 4, -1, 8, -1, 0, Fr_rawq);
    mpz_invert(mr, ma, q);
    Fr_fromMpz(r, mr);
    mpz_clear(ma); mpz_clear(mr); mpz_clear(q);
}

extern "C" void Fr_div(PFrElement r, PFrElement a, PFrElement b) {
    FrElement inv_b;
    Fr_inv(&inv_b, b);
    Fr_mul(r, a, &inv_b);
}

extern "C" void Fr_pow(PFrElement r, PFrElement a, PFrElement b) {
    mpz_t ma, mb, mr, q;
    mpz_init(ma); mpz_init(mb); mpz_init(mr); mpz_init(q);
    Fr_toMpz(ma, a);
    Fr_toMpz(mb, b);
    mpz_import(q, 4, -1, 8, -1, 0, Fr_rawq);
    mpz_powm(mr, ma, mb, q);
    Fr_fromMpz(r, mr);
    mpz_clear(ma); mpz_clear(mb); mpz_clear(mr); mpz_clear(q);
}

// ============================================================================
// String conversion
// ============================================================================

extern "C" void Fr_str2element(PFrElement r, const char *s) {
    mpz_t v, q;
    mpz_init(v);
    mpz_init(q);
    mpz_import(q, 4, -1, 8, -1, 0, Fr_rawq);
    
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        mpz_set_str(v, s + 2, 16);
    } else {
        mpz_set_str(v, s, 10);
    }
    mpz_mod(v, v, q);
    Fr_fromMpz(r, v);
    
    mpz_clear(v);
    mpz_clear(q);
}

extern "C" char* Fr_element2str(PFrElement a) {
    FrElement tmp;
    Fr_toLongNormalInternal(&tmp, a);
    
    mpz_t v;
    mpz_init(v);
    mpz_import(v, 4, -1, 8, -1, 0, tmp.longVal);
    
    char *str = mpz_get_str(NULL, 10, v);
    mpz_clear(v);
    return str;
}

// ============================================================================
// Initialization
// ============================================================================

extern "C" void Fr_init() {
    // Nothing to initialize - constants are statically defined
}
