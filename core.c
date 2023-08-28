#include <string.h>
#include <stdlib.h>
#include <math.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#include <machine/types.h>
#endif
#include <netinet/in.h>
#include "ruby.h"

#define ROUNDS 16
#define SUBKEYCOUNT (ROUNDS+2)
#define SUBKEYSIZE 4
#define SBOXSIZE 256
#define SBOXCOUNT 4
#define SBOXENTRYSIZE 4

//#define DEBUG 1

/**
 * @brief
 *
 */
ID encrypt_id;

/**
 * @brief
 *
 */
ID decrypt_id;

uint32_t core_function(uint32_t *sboxes, unsigned char *i_p) {
    return htonl((
            (
                sboxes[(0 * SBOXSIZE) + i_p[0]] +
                sboxes[(1 * SBOXSIZE) + i_p[1]]
            ) ^
            sboxes[(2 * SBOXSIZE) + i_p[2]]
        ) +
        sboxes[(3 * SBOXSIZE) + i_p[3]]);
}



#define SUBKEYARRAYSIZE	(SUBKEYCOUNT * SUBKEYSIZE)
#define SBOXARRAYSIZE	(SBOXCOUNT * SBOXSIZE * SBOXENTRYSIZE)

/*
 * This tells the caller how many fraction digit bytes of Pi are needed to
 * start up the subkeys/sboxes
 */
static VALUE cb_c_needed_pi_digits(VALUE self) {
    return INT2FIX(SUBKEYARRAYSIZE + SBOXARRAYSIZE);
}

static VALUE cb_initialise(VALUE self, VALUE pi_digit_s) {
    int i;
#if DEBUG
    printf("Init\n");
#endif
    char *subkey_chunk = RSTRING_PTR(pi_digit_s);

    VALUE new_subkeys = rb_str_new(subkey_chunk,
        SUBKEYARRAYSIZE);

    uint32_t *sboxes_32b = (uint32_t *)(subkey_chunk + SUBKEYARRAYSIZE);
    uint32_t sboxes_32b_out[SBOXCOUNT * SBOXSIZE];
    for(i = 0; i < (SBOXCOUNT * SBOXSIZE); i++) {
        sboxes_32b_out[i] = ntohl(sboxes_32b[i]);
    }
    VALUE new_sboxes = rb_str_new((char *)sboxes_32b_out, SBOXARRAYSIZE);
#if DEBUG
    printf("PI %u%u%u%u\n", subkey_chunk[0], subkey_chunk[1], subkey_chunk[2], subkey_chunk[3]);
#endif
    rb_iv_set(self, "@subkeys", new_subkeys);
    rb_iv_set(self, "@sboxes", new_sboxes);
    return self;
}

uint32_t *bf_crypt(uint32_t *subkeys, uint32_t *sboxes, uint32_t *to_encrypt, char mode, uint32_t *dest) {
    dest[0] = to_encrypt[0];
    dest[1] = to_encrypt[1];
    uint32_t x_tmp;
    int i;

    if(mode == 'e') {
#if DEBUG
        printf("i %u %u\n", dest[0], dest[1]);
#endif
        for(i = 0; i < ROUNDS; i += 2) {

            dest[0] ^= subkeys[i];
#if DEBUG
            printf("q %u %u\n", subkeys[i], core_function(sboxes, (unsigned char *)dest));
#endif
            dest[1] ^= core_function(sboxes, (unsigned char *)dest);
#if DEBUG
            printf("r %u %u\n", dest[0], dest[1]);
#endif
            /* Implicit flip here */
            dest[1] ^= subkeys[i+1];
#if DEBUG
            printf("q %u %u\n", subkeys[i+1], core_function(sboxes, (unsigned char *)(dest + 1)));
#endif
            dest[0] ^= core_function(sboxes, (unsigned char *)(dest + 1));
#if DEBUG
            printf("r %u %u\n", dest[1], dest[0]);
#endif
        }
        x_tmp = dest[0];
        dest[0] = dest[1] ^ subkeys[ROUNDS + 1];
        dest[1] = x_tmp ^ subkeys[ROUNDS];

    } else {
        for(i = ROUNDS + 1; i > 1; i -= 2) {
            dest[0] ^= subkeys[i];
#if DEBUG
            printf("q %u %u\n", subkeys[i], core_function(sboxes, (unsigned char *)dest));
#endif
            dest[1] ^= core_function(sboxes, (unsigned char *)dest);
#if DEBUG
            printf("r %u %u\n", dest[0], dest[1]);
#endif

            /* Implicit flip here */
            dest[1] ^= subkeys[i - 1];
#if DEBUG
            printf("q %u %u\n", subkeys[i - 1], core_function(sboxes, (unsigned char *)(dest + 1)));
#endif
            dest[0] ^= core_function(sboxes, (unsigned char *)(dest + 1));
#if DEBUG
            printf("r %u %u\n", dest[1], dest[0]);
#endif
        }
        x_tmp = dest[0];
        dest[0] = dest[1] ^ subkeys[0];
        dest[1] = x_tmp ^ subkeys[1];
    }
    return dest;
}

VALUE cb_crypt(VALUE self, VALUE string, VALUE mode) {
    uint32_t *i_p = (uint32_t *)RSTRING_PTR(string);
    uint32_t dest[2];
    uint32_t *sboxes = (uint32_t *)RSTRING_PTR(rb_iv_get(self, "@sboxes"));
    uint32_t *subkeys = (uint32_t *)RSTRING_PTR(rb_iv_get(self, "@subkeys"));
#if DEBUG
    printf("SKE %u %u\n", subkeys[0], sboxes[0]);
#endif
    Check_Type(mode, T_SYMBOL);
    ID mode_i = SYM2ID(mode);

    if(mode_i == encrypt_id) {
        bf_crypt(subkeys, sboxes, i_p, 'e', dest);
    } else if(mode_i == decrypt_id) {
        bf_crypt(subkeys, sboxes, i_p, 'd', dest);
    } else {
        rb_raise(rb_eRuntimeError, "Invalid symbol for mode");
    }
    return rb_str_new((char *)dest, 8);
}

static VALUE cb_update_from_key(VALUE self, VALUE key_str) {
    uint32_t new_subkeys[SUBKEYCOUNT];
    uint32_t *key_chunks=(uint32_t *)RSTRING_PTR(key_str);
    uint32_t *subkeys=(uint32_t *)RSTRING_PTR(rb_iv_get(self, "@subkeys"));
    uint32_t *sboxes = (uint32_t *)RSTRING_PTR(rb_iv_get(self, "@sboxes"));
    int i;
    /*
     * For each chunk of the key, XOR it into new_subkeys, repeating
     * as necessary.
     */

    // We need this so that we can flip back and forth over the key
    unsigned long key_chunk_count = RSTRING_LEN(key_str) / sizeof(uint32_t);
    for(i = 0; i < SUBKEYCOUNT; i++) {
        new_subkeys[i] = subkeys[i] ^ key_chunks[i % key_chunk_count];
    }
#if DEBUG
    printf("SK %u %u %u %u %u %u(%i)\n", new_subkeys[0], new_subkeys[1], new_subkeys[2], key_chunks[0], key_chunks[1], key_chunks[2],
        RSTRING_LEN(key_str));
#endif
    /*
     * For all the subkeys, then the s-boxes, replace the contents
     * with the results of an encryption of the current magic value
     * (replacing the magic value also)
     */
    uint32_t *keygen_magic = calloc(2, sizeof(uint32_t));
    for(i = 0; i < SUBKEYCOUNT; i += 2) {
        bf_crypt(new_subkeys, sboxes, keygen_magic, 'e', keygen_magic);
        memcpy(new_subkeys + i, keygen_magic, 8);
    }
#if DEBUG
    printf("SKM %u %u\n", new_subkeys[0], sboxes[0]);
#endif

#if DEBUG
    printf("subkeys done\n");
#endif
    for(i = 0; i < SBOXCOUNT * SBOXSIZE; i += 2) {
        bf_crypt(new_subkeys, sboxes, keygen_magic, 'e', keygen_magic);
        sboxes[i] = ntohl(keygen_magic[0]);
        sboxes[i + 1] = ntohl(keygen_magic[1]);
    }
#if DEBUG
    printf("sboxes done\n");
#endif
    VALUE subkeys_rs = rb_str_new((char *)new_subkeys, SUBKEYCOUNT * 4);
    rb_iv_set(self, "@subkeys", subkeys_rs);
#if DEBUG
    printf("SKO %u %u\n", new_subkeys[0], sboxes[0]);
#endif
    return self;
}

static VALUE cb_subkeys(VALUE self) {
    return rb_iv_get(self, "@subkeys");
}

static VALUE cb_sboxes(VALUE self) {
    return rb_iv_get(self, "@sboxes");
}

void Init_core() {
    VALUE cCrypt = rb_define_class("JdCrypt", rb_cObject);
    VALUE cCB = rb_define_class_under(cCrypt, "Blowfish", rb_cObject);
    VALUE cFoo = rb_define_class_under(cCB, "Core", rb_cObject);
    rb_define_method(cFoo, "initialize", cb_initialise, 1);
    rb_define_method(cFoo, "crypt", cb_crypt, 2);
    rb_define_method(cFoo, "update_from_key", cb_update_from_key, 1);
    rb_define_method(cFoo, "subkeys", cb_subkeys, 0);
    rb_define_method(cFoo, "sboxes", cb_sboxes, 0);
    rb_define_module_function(cFoo,
        "needed_pi_digits", cb_c_needed_pi_digits, 0);

    decrypt_id = rb_intern("decrypt");
    encrypt_id = rb_intern("encrypt");
}
