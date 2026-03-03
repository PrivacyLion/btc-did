/**
 * fr_generic.cpp - Pure C++ implementation of BN254 scalar field operations
 * 
 * This file provides portable implementations of the Fr operations normally
 * in fr.asm (x86 assembly). Use this for ARM64/Android builds.
 * 
 * Build: Replace fr.asm and fr_asm.o with this file in the Makefile
 * 
 * Field: BN254 scalar field (Fr)
 * Prime q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */

#include "fr.hpp"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <gmp.h>

// Global field modulus for high-level operations
static mpz_t g_q;
static mpz_t g_zero;
static mpz_t g_one;
static bool g_initialized = false;

static void ensure_initialized() {
    if (!g_initialized) {
        mpz_init(g_q);
        mpz_init(g_zero);
        mpz_init(g_one);
        mpz_import(g_q, Fr_N64, -1, 8, -1, 0, Fr_rawq);
        mpz_set_ui(g_zero, 0);
        mpz_set_ui(g_one, 1);
        g_initialized = true;
    }
}

// Field modulus q for BN254 Fr
static const uint64_t Fr_rawq_data[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL
};

// R = 2^256 mod q (Montgomery constant)
static const uint64_t Fr_R_data[4] = {
    0xd35d438dc58f0d9dULL,
    0x0a78eb28f5c70b3dULL,
    0x666ea36f7879462cULL,
    0x0e0a77c19a07df2fULL
};

// R^2 mod q
static const uint64_t Fr_R2_data[4] = {
    0x1bb8e645ae216da7ULL,
    0x53fe3ab1e35c59e3ULL,
    0x8c49833d53bb8085ULL,
    0x0216d0b17f4e44a5ULL
};

// R^3 mod q
static const uint64_t Fr_R3_data[4] = {
    0x5e94d8e1b4bf0040ULL,
    0x2a489cbe1cfbb6b8ULL,
    0x893cc664a19fcfedULL,
    0x0cf8594b7fcc657cULL
};

// Exported globals
FrElement Fr_q = {0, Fr_LONGMONTGOMERY, {Fr_rawq_data[0], Fr_rawq_data[1], Fr_rawq_data[2], Fr_rawq_data[3]}};
FrElement Fr_R3 = {0, Fr_LONGMONTGOMERY, {Fr_R3_data[0], Fr_R3_data[1], Fr_R3_data[2], Fr_R3_data[3]}};
FrRawElement Fr_rawq = {Fr_rawq_data[0], Fr_rawq_data[1], Fr_rawq_data[2], Fr_rawq_data[3]};
FrRawElement Fr_rawR3 = {Fr_R3_data[0], Fr_R3_data[1], Fr_R3_data[2], Fr_R3_data[3]};

// Helper: compare two raw elements (returns -1, 0, or 1)
static inline int raw_cmp(const FrRawElement a, const FrRawElement b) {
    for (int i = Fr_N64 - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

// Helper: check if raw element is zero
static inline int raw_isZero(const FrRawElement a) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

// Helper: add with carry
static inline uint64_t adc(uint64_t a, uint64_t b, uint64_t *carry) {
    __uint128_t sum = (__uint128_t)a + b + *carry;
    *carry = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

// Helper: subtract with borrow
static inline uint64_t sbb(uint64_t a, uint64_t b, uint64_t *borrow) {
    __uint128_t diff = (__uint128_t)a - b - *borrow;
    *borrow = (diff >> 64) ? 1 : 0;
    return (uint64_t)diff;
}

// Helper: multiply-add with carry
static inline uint64_t mac(uint64_t a, uint64_t b, uint64_t c, uint64_t *carry) {
    __uint128_t prod = (__uint128_t)b * c + a + *carry;
    *carry = (uint64_t)(prod >> 64);
    return (uint64_t)prod;
}

extern "C" void Fr_rawCopy(FrRawElement r, const FrRawElement a) {
    r[0] = a[0]; r[1] = a[1]; r[2] = a[2]; r[3] = a[3];
}

extern "C" void Fr_rawZero(FrRawElement r) {
    r[0] = r[1] = r[2] = r[3] = 0;
}

extern "C" void Fr_rawSwap(FrRawElement a, FrRawElement b) {
    uint64_t t;
    for (int i = 0; i < Fr_N64; i++) {
        t = a[i]; a[i] = b[i]; b[i] = t;
    }
}

// Raw addition: r = a + b mod q
extern "C" void Fr_rawAdd(FrRawElement r, const FrRawElement a, const FrRawElement b) {
    uint64_t carry = 0;
    r[0] = adc(a[0], b[0], &carry);
    r[1] = adc(a[1], b[1], &carry);
    r[2] = adc(a[2], b[2], &carry);
    r[3] = adc(a[3], b[3], &carry);
    
    // Reduce if >= q
    if (carry || raw_cmp(r, Fr_rawq) >= 0) {
        uint64_t borrow = 0;
        r[0] = sbb(r[0], Fr_rawq[0], &borrow);
        r[1] = sbb(r[1], Fr_rawq[1], &borrow);
        r[2] = sbb(r[2], Fr_rawq[2], &borrow);
        r[3] = sbb(r[3], Fr_rawq[3], &borrow);
    }
}

// Raw subtraction: r = a - b mod q
extern "C" void Fr_rawSub(FrRawElement r, const FrRawElement a, const FrRawElement b) {
    uint64_t borrow = 0;
    r[0] = sbb(a[0], b[0], &borrow);
    r[1] = sbb(a[1], b[1], &borrow);
    r[2] = sbb(a[2], b[2], &borrow);
    r[3] = sbb(a[3], b[3], &borrow);
    
    // If underflow, add q
    if (borrow) {
        uint64_t carry = 0;
        r[0] = adc(r[0], Fr_rawq[0], &carry);
        r[1] = adc(r[1], Fr_rawq[1], &carry);
        r[2] = adc(r[2], Fr_rawq[2], &carry);
        r[3] = adc(r[3], Fr_rawq[3], &carry);
    }
}

// Raw negation: r = -a mod q
extern "C" void Fr_rawNeg(FrRawElement r, const FrRawElement a) {
    if (raw_isZero(a)) {
        Fr_rawZero(r);
        return;
    }
    uint64_t borrow = 0;
    r[0] = sbb(Fr_rawq[0], a[0], &borrow);
    r[1] = sbb(Fr_rawq[1], a[1], &borrow);
    r[2] = sbb(Fr_rawq[2], a[2], &borrow);
    r[3] = sbb(Fr_rawq[3], a[3], &borrow);
}

// Montgomery multiplication: r = a * b * R^(-1) mod q
extern "C" void Fr_rawMMul(FrRawElement r, const FrRawElement a, const FrRawElement b) {
    // Montgomery multiplication: r = (a * b * R^(-1)) mod q
    // where R = 2^256 (for 4x64-bit limbs)
    mpz_t ma, mb, mq, mr, mR, mRinv;
    mpz_init(ma); mpz_init(mb); mpz_init(mq); mpz_init(mr); mpz_init(mR); mpz_init(mRinv);
    
    mpz_import(ma, Fr_N64, -1, 8, -1, 0, a);
    mpz_import(mb, Fr_N64, -1, 8, -1, 0, b);
    mpz_import(mq, Fr_N64, -1, 8, -1, 0, Fr_rawq);
    
    // R = 2^256
    mpz_set_ui(mR, 1);
    mpz_mul_2exp(mR, mR, 256);
    
    // Compute R^(-1) mod q
    mpz_invert(mRinv, mR, mq);
    
    // Montgomery multiplication: (a * b * R^(-1)) mod q
    mpz_mul(mr, ma, mb);
    mpz_mul(mr, mr, mRinv);
    mpz_mod(mr, mr, mq);
    
    // Extract result
    size_t count;
    Fr_rawZero(r);
    mpz_export(r, &count, -1, 8, -1, 0, mr);
    
    mpz_clear(ma); mpz_clear(mb); mpz_clear(mq); mpz_clear(mr); mpz_clear(mR); mpz_clear(mRinv);
}

// Montgomery square: r = a^2 * R^(-1) mod q
extern "C" void Fr_rawMSquare(FrRawElement r, const FrRawElement a) {
    Fr_rawMMul(r, a, a);
}

// To Montgomery form: r = a * R mod q
extern "C" void Fr_rawToMontgomery(FrRawElement r, const FrRawElement &a) {
    Fr_rawMMul(r, a, Fr_R2_data);
}

// From Montgomery form: r = a * R^(-1) mod q
extern "C" void Fr_rawFromMontgomery(FrRawElement r, const FrRawElement &a) {
    static const uint64_t one[4] = {1, 0, 0, 0};
    Fr_rawMMul(r, a, one);
}

extern "C" int Fr_rawIsEq(const FrRawElement a, const FrRawElement b) {
    return raw_cmp(a, b) == 0 ? 1 : 0;
}

extern "C" int Fr_rawIsZero(const FrRawElement a) {
    return raw_isZero(a) ? 1 : 0;
}

// ============================================================================
// High-level Fr operations (work with FrElement)
// ============================================================================

extern "C" void Fr_copy(PFrElement r, PFrElement a) {
    *r = *a;
}

extern "C" void Fr_copyn(PFrElement r, PFrElement a, int n) {
    memcpy(r, a, n * sizeof(FrElement));
}

static void Fr_toLongNormalInternal(FrElement *r, const FrElement *a) {
    if (a->type & Fr_LONG) {
        if (a->type == Fr_LONGMONTGOMERY) {
            Fr_rawFromMontgomery(r->longVal, a->longVal);
        } else {
            Fr_rawCopy(r->longVal, a->longVal);
        }
    } else {
        r->longVal[0] = (a->shortVal < 0) ? -((int64_t)a->shortVal) : a->shortVal;
        r->longVal[1] = r->longVal[2] = r->longVal[3] = 0;
        if (a->shortVal < 0) {
            Fr_rawNeg(r->longVal, r->longVal);
        }
    }
    r->type = Fr_LONG;
    r->shortVal = 0;
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

extern "C" void Fr_toMontgomery(PFrElement r, PFrElement a) {
    if (a->type == Fr_LONGMONTGOMERY) {
        *r = *a;
        return;
    }
    if (a->type & Fr_LONG) {
        Fr_rawToMontgomery(r->longVal, a->longVal);
    } else {
        FrRawElement tmp = {0, 0, 0, 0};
        tmp[0] = (a->shortVal < 0) ? -((int64_t)a->shortVal) : a->shortVal;
        if (a->shortVal < 0) {
            Fr_rawNeg(tmp, tmp);
        }
        Fr_rawToMontgomery(r->longVal, tmp);
    }
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" int Fr_toInt(PFrElement a) {
    FrElement tmp;
    Fr_toNormal(&tmp, a);
    if (tmp.type & Fr_LONG) {
        // Check if fits in int32
        if (tmp.longVal[1] == 0 && tmp.longVal[2] == 0 && tmp.longVal[3] == 0) {
            if (tmp.longVal[0] <= 0x7FFFFFFF) {
                return (int32_t)tmp.longVal[0];
            }
        }
        // Check if it's a negative number (close to q)
        uint64_t borrow = 0;
        FrRawElement neg;
        neg[0] = sbb(Fr_rawq[0], tmp.longVal[0], &borrow);
        neg[1] = sbb(Fr_rawq[1], tmp.longVal[1], &borrow);
        neg[2] = sbb(Fr_rawq[2], tmp.longVal[2], &borrow);
        neg[3] = sbb(Fr_rawq[3], tmp.longVal[3], &borrow);
        if (neg[1] == 0 && neg[2] == 0 && neg[3] == 0 && neg[0] <= 0x80000000ULL) {
            return -(int32_t)neg[0];
        }
        return 0; // Overflow
    }
    return tmp.shortVal;
}

extern "C" int Fr_isTrue(PFrElement a) {
    FrElement tmp;
    Fr_toNormal(&tmp, a);
    if (tmp.type & Fr_LONG) {
        return !raw_isZero(tmp.longVal);
    }
    return tmp.shortVal != 0;
}

// Convert both to Montgomery form and do operation
static void Fr_prepareOp(FrElement *ma, FrElement *mb, PFrElement a, PFrElement b) {
    Fr_toMontgomery(ma, a);
    Fr_toMontgomery(mb, b);
}

extern "C" void Fr_add(PFrElement r, PFrElement a, PFrElement b) {
    FrElement ma, mb;
    Fr_prepareOp(&ma, &mb, a, b);
    Fr_rawAdd(r->longVal, ma.longVal, mb.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_sub(PFrElement r, PFrElement a, PFrElement b) {
    FrElement ma, mb;
    Fr_prepareOp(&ma, &mb, a, b);
    Fr_rawSub(r->longVal, ma.longVal, mb.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_neg(PFrElement r, PFrElement a) {
    FrElement ma;
    Fr_toMontgomery(&ma, a);
    Fr_rawNeg(r->longVal, ma.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_mul(PFrElement r, PFrElement a, PFrElement b) {
    FrElement ma, mb;
    Fr_prepareOp(&ma, &mb, a, b);
    Fr_rawMMul(r->longVal, ma.longVal, mb.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

extern "C" void Fr_square(PFrElement r, PFrElement a) {
    FrElement ma;
    Fr_toMontgomery(&ma, a);
    Fr_rawMSquare(r->longVal, ma.longVal);
    r->type = Fr_LONGMONTGOMERY;
    r->shortVal = 0;
}

// Bitwise operations (work in normal form)
extern "C" void Fr_band(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->longVal[0] = na.longVal[0] & nb.longVal[0];
    r->longVal[1] = na.longVal[1] & nb.longVal[1];
    r->longVal[2] = na.longVal[2] & nb.longVal[2];
    r->longVal[3] = na.longVal[3] & nb.longVal[3];
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_bor(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->longVal[0] = na.longVal[0] | nb.longVal[0];
    r->longVal[1] = na.longVal[1] | nb.longVal[1];
    r->longVal[2] = na.longVal[2] | nb.longVal[2];
    r->longVal[3] = na.longVal[3] | nb.longVal[3];
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_bxor(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->longVal[0] = na.longVal[0] ^ nb.longVal[0];
    r->longVal[1] = na.longVal[1] ^ nb.longVal[1];
    r->longVal[2] = na.longVal[2] ^ nb.longVal[2];
    r->longVal[3] = na.longVal[3] ^ nb.longVal[3];
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_bnot(PFrElement r, PFrElement a) {
    FrElement na;
    Fr_toLongNormalInternal(&na, a);
    r->longVal[0] = ~na.longVal[0];
    r->longVal[1] = ~na.longVal[1];
    r->longVal[2] = ~na.longVal[2];
    r->longVal[3] = ~na.longVal[3];
    // Reduce mod q
    if (raw_cmp(r->longVal, Fr_rawq) >= 0) {
        Fr_rawSub(r->longVal, r->longVal, Fr_rawq);
    }
    r->type = Fr_LONG;
    r->shortVal = 0;
}

extern "C" void Fr_shl(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    
    int shift = Fr_toInt(&nb);
    if (shift < 0 || shift >= 256) {
        Fr_rawZero(r->longVal);
        r->type = Fr_LONG;
        r->shortVal = 0;
        return;
    }
    
    mpz_t m;
    mpz_init(m);
    mpz_import(m, Fr_N64, -1, 8, -1, 0, na.longVal);
    mpz_mul_2exp(m, m, shift);
    
    mpz_t mq;
    mpz_init(mq);
    mpz_import(mq, Fr_N64, -1, 8, -1, 0, Fr_rawq);
    mpz_mod(m, m, mq);
    
    Fr_rawZero(r->longVal);
    mpz_export(r->longVal, NULL, -1, 8, -1, 0, m);
    r->type = Fr_LONG;
    r->shortVal = 0;
    
    mpz_clear(m);
    mpz_clear(mq);
}

extern "C" void Fr_shr(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    
    int shift = Fr_toInt(&nb);
    if (shift < 0 || shift >= 256) {
        Fr_rawZero(r->longVal);
        r->type = Fr_LONG;
        r->shortVal = 0;
        return;
    }
    
    mpz_t m;
    mpz_init(m);
    mpz_import(m, Fr_N64, -1, 8, -1, 0, na.longVal);
    mpz_fdiv_q_2exp(m, m, shift);
    
    Fr_rawZero(r->longVal);
    mpz_export(r->longVal, NULL, -1, 8, -1, 0, m);
    r->type = Fr_LONG;
    r->shortVal = 0;
    
    mpz_clear(m);
}

// Comparison operations
extern "C" void Fr_eq(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->type = Fr_SHORT;
    r->shortVal = Fr_rawIsEq(na.longVal, nb.longVal) ? 1 : 0;
}

extern "C" void Fr_neq(PFrElement r, PFrElement a, PFrElement b) {
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    r->type = Fr_SHORT;
    r->shortVal = Fr_rawIsEq(na.longVal, nb.longVal) ? 0 : 1;
}

// Field comparison: uses signed semantics for SHORT values
// For LONG values, values > (q-1)/2 are considered "negative"
static const uint64_t Fr_half[4] = {
    0xa1f0fac9f8000000ULL, 0x9419f4243cdcb848ULL,
    0xdc2822db40c0ac2eULL, 0x183227397098d014ULL
};

static int Fr_IsNegative(const FrRawElement a) {
    // Returns 1 if a > (q-1)/2, meaning it represents a negative field element
    return raw_cmp(a, Fr_half) > 0;
}

static int Fr_cmp(PFrElement a, PFrElement b) {
    // Returns -1, 0, or 1 for a < b, a == b, a > b using field semantics
    
    // Both SHORT: simple signed comparison
    if (!(a->type & Fr_LONG) && !(b->type & Fr_LONG)) {
        if (a->shortVal < b->shortVal) return -1;
        if (a->shortVal > b->shortVal) return 1;
        return 0;
    }
    
    // Convert both to normal form for comparison
    FrElement na, nb;
    Fr_toLongNormalInternal(&na, a);
    Fr_toLongNormalInternal(&nb, b);
    
    // Check "sign" (negative if > half)
    int a_neg = Fr_IsNegative(na.longVal);
    int b_neg = Fr_IsNegative(nb.longVal);
    
    if (a_neg && !b_neg) return -1;  // negative < positive
    if (!a_neg && b_neg) return 1;   // positive > negative
    
    // Same sign: raw compare (both positive or both negative)
    int cmp = raw_cmp(na.longVal, nb.longVal);
    return a_neg ? -cmp : cmp;  // if both negative, flip comparison
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

// Logical operations
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

extern "C" void Fr_fail() {
    // Called when circuit constraint fails
    fprintf(stderr, "Fr_fail: Circuit constraint violated\n");
    abort();
}

// Montgomery mul by single limb
extern "C" void Fr_rawMMul1(FrRawElement r, const FrRawElement a, uint64_t b) {
    FrRawElement tmp = {b, 0, 0, 0};
    Fr_rawMMul(r, a, tmp);
}

// ============================================================================
// High-level helper functions (for Fr_str2element, Fr_div, etc.)
// ============================================================================

// Convert FrElement to GMP mpz_t
void Fr_toMpz(mpz_t r, PFrElement pE) {
    ensure_initialized();
    FrElement tmp;
    Fr_toNormal(&tmp, pE);
    if (!(tmp.type & Fr_LONG)) {
        mpz_set_si(r, tmp.shortVal);
        if (tmp.shortVal < 0) {
            mpz_add(r, r, g_q);
        }
    } else {
        mpz_import(r, Fr_N64, -1, 8, -1, 0, (const void *)tmp.longVal);
    }
}

// Convert GMP mpz_t to FrElement
void Fr_fromMpz(PFrElement pE, mpz_t v) {
    if (mpz_fits_sint_p(v)) {
        pE->type = Fr_SHORT;
        pE->shortVal = mpz_get_si(v);
    } else {
        pE->type = Fr_LONG;
        for (int i = 0; i < Fr_N64; i++) pE->longVal[i] = 0;
        mpz_export((void *)(pE->longVal), NULL, -1, 8, -1, 0, v);
    }
}

// Parse string to field element
void Fr_str2element(PFrElement pE, char const *s, uint base) {
    ensure_initialized();
    mpz_t mr;
    mpz_init_set_str(mr, s, base);
    mpz_fdiv_r(mr, mr, g_q);
    Fr_fromMpz(pE, mr);
    mpz_clear(mr);
}

// Convert field element to string (caller must delete[] result)
char *Fr_element2str(PFrElement pE) {
    ensure_initialized();
    FrElement tmp;
    mpz_t r;
    if (!(pE->type & Fr_LONG)) {
        if (pE->shortVal >= 0) {
            char *res = new char[32];
            sprintf(res, "%d", pE->shortVal);
            return res;
        } else {
            mpz_init_set_si(r, pE->shortVal);
            mpz_add(r, r, g_q);
        }
    } else {
        Fr_toNormal(&tmp, pE);
        mpz_init(r);
        mpz_import(r, Fr_N64, -1, 8, -1, 0, (const void *)tmp.longVal);
    }
    char *res = mpz_get_str(0, 10, r);
    mpz_clear(r);
    return res;
}

// Integer division: r = a / b (integer, not field)
void Fr_idiv(PFrElement r, PFrElement a, PFrElement b) {
    ensure_initialized();
    mpz_t ma, mb, mr;
    mpz_init(ma);
    mpz_init(mb);
    mpz_init(mr);

    Fr_toMpz(ma, a);
    Fr_toMpz(mb, b);
    mpz_fdiv_q(mr, ma, mb);
    Fr_fromMpz(r, mr);

    mpz_clear(ma);
    mpz_clear(mb);
    mpz_clear(mr);
}

// Modulo: r = a % b
void Fr_mod(PFrElement r, PFrElement a, PFrElement b) {
    ensure_initialized();
    mpz_t ma, mb, mr;
    mpz_init(ma);
    mpz_init(mb);
    mpz_init(mr);

    Fr_toMpz(ma, a);
    Fr_toMpz(mb, b);
    mpz_fdiv_r(mr, ma, mb);
    Fr_fromMpz(r, mr);

    mpz_clear(ma);
    mpz_clear(mb);
    mpz_clear(mr);
}

// Power: r = a^b mod q
void Fr_pow(PFrElement r, PFrElement a, PFrElement b) {
    ensure_initialized();
    mpz_t ma, mb, mr;
    mpz_init(ma);
    mpz_init(mb);
    mpz_init(mr);

    Fr_toMpz(ma, a);
    Fr_toMpz(mb, b);
    mpz_powm(mr, ma, mb, g_q);
    Fr_fromMpz(r, mr);

    mpz_clear(ma);
    mpz_clear(mb);
    mpz_clear(mr);
}

// Inverse: r = a^(-1) mod q
void Fr_inv(PFrElement r, PFrElement a) {
    ensure_initialized();
    mpz_t ma, mr;
    mpz_init(ma);
    mpz_init(mr);

    Fr_toMpz(ma, a);
    mpz_invert(mr, ma, g_q);
    Fr_fromMpz(r, mr);

    mpz_clear(ma);
    mpz_clear(mr);
}

// Field division: r = a / b = a * b^(-1) mod q
void Fr_div(PFrElement r, PFrElement a, PFrElement b) {
    FrElement tmp;
    Fr_inv(&tmp, b);
    Fr_mul(r, a, &tmp);
}
