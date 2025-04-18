/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kvstore.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "kvstore_securekvs.h"

#if PICO_ON_DEVICE
#include "pico/rand.h"
#include "pico/unique_id.h"
#else
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#endif

#define SECURESTORE_REVISION 1
#define GCM_TAG_SIZE 16
#define SCRATCH_BUF_SIZE 256
#define DERIVED_KEY_SIZE (128 / 8)

#ifndef MIN
#define MIN(a, b) ((a < b) ? a : b)
#endif


static const char *ENCRYPT_PREFIX = "ENC";

static const uint32_t SECURITY_FLAGS =
    KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG | KVSTORE_REQUIRE_REPLAY_PROTECTION_FLAG;

/*
 * NOTE: The pico-sdk in the host environment does not include pico_rand,
 *       pico_mbedtls_crypto, or pico_unique_id, so they need to be followed.
 */
#if !PICO_ON_DEVICE

typedef uint8_t rng_128_t;

void get_rand_128(rng_128_t *rand) {
    uint8_t *out = rand;
    int ret = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "my_random_personalization";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        fprintf(stderr, "mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
        goto cleanup;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, 16);
    if (ret != 0)
    {
        fprintf(stderr, "mbedtls_ctr_drbg_random failed: -0x%04x\n", -ret);
        goto cleanup;
    }
cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return;
}
#endif

static int pico_unique_id_loader(uint8_t *key) {
    // NOTE: IS NOT SECURE
    memset(key, 0, DERIVED_KEY_SIZE);
#if PICO_ON_DEVICE
    pico_get_unique_board_id((pico_unique_board_id_t *)key);
#endif
    return 0;
}

static int create_derive_key(kvs_securekvs_context_t *ctx, uint8_t *salt_buf, size_t salt_buf_size,
                             uint8_t *encrypt_key, size_t encrypt_key_size, uint8_t *derive_key,
                             size_t derive_key_size) {
    int ret;

    if (ctx->secretkey_loader != NULL) {
        ret = ctx->secretkey_loader(encrypt_key);
        if (ret) {
            return ret;
        }
    } else {
        pico_unique_id_loader(encrypt_key);
    }
    return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt_buf, salt_buf_size,
                        encrypt_key, encrypt_key_size, NULL, 0, derive_key, derive_key_size);
}

static bool is_valid_key(const char *key) {
    if (key == NULL)
        return false;
    if (strlen(key) == 0)
        return false;
    if (strlen(key) > 128)
        return false;
    return true;
}

static int gcm_init_and_starts(kvs_securekvs_context_t *ctx, mbedtls_gcm_context *gcm_ctx,
                               const uint8_t *iv, size_t iv_len, const uint8_t *key_data,
                               size_t key_bits, const void *aad, size_t aad_len,
                               int encrypt) {
    (void)ctx;
    (void)aad;
    (void)aad_len;
    int ret;
    mbedtls_gcm_init(gcm_ctx);
    ret = mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES, key_data, key_bits);
    if (ret != 0) {
        return ret;
    }
    ret = mbedtls_gcm_starts(gcm_ctx, encrypt, iv, iv_len, aad, aad_len);
    if (ret != 0) {
        return ret;
    }
    return ret;
}

static int gcm_update_chunk(mbedtls_gcm_context *gcm_ctx, const uint8_t *input, uint8_t *output,
                            size_t length) {
    return mbedtls_gcm_update(gcm_ctx, length, input, output);
}

static int gcm_finish_and_tag(mbedtls_gcm_context *gcm_ctx, uint8_t *tag, size_t tag_len) {
    return mbedtls_gcm_finish(gcm_ctx, tag, tag_len);
}

static int gcm_finish_and_check_tag(mbedtls_gcm_context *gcm_ctx, const uint8_t *tag,
                                    size_t tag_len) {
    uint8_t calc_tag[GCM_TAG_SIZE];
    int ret = mbedtls_gcm_finish(gcm_ctx, calc_tag, tag_len);
    if (ret != 0) {
        return ret;
    }
    if (memcmp(calc_tag, tag, tag_len) != 0) {
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    return 0;
}

static int set_start(kvs_t *kvs, kvs_inc_set_handle_t *handle, const char *key,
                     size_t final_data_size, uint32_t flags) {
    kvs_securekvs_context_t *ctx = kvs->context;

    int os_ret = 0;
    bool enc_started = false;

    // mutex.lock()

    int ret;
    size_t unused_actual_size;
    (void)unused_actual_size;
    kvs_t *underlying_kvs = ctx->underlying_kvs;
    ret = underlying_kvs->get(underlying_kvs, key, &(ctx->ih->metadata), sizeof(record_metadata_t),
                              &unused_actual_size, 0);
    if (ret == KVSTORE_SUCCESS) {
        if (!(flags & KVSTORE_REQUIRE_REPLAY_PROTECTION_FLAG) &&
            (ctx->ih->metadata.create_flags & KVSTORE_REQUIRE_REPLAY_PROTECTION_FLAG)) {
            ret = KVSTORE_ERROR_INVALID_ARGUMENT;
            goto fail;
        }
        if (ctx->ih->metadata.create_flags & KVSTORE_WRITE_ONCE_FLAG) {
            ret = KVSTORE_ERROR_WRITE_PROTECTED;
            goto fail;
        }
    }

    ctx->ih->metadata.create_flags = flags;
    ctx->ih->metadata.data_size = final_data_size + GCM_TAG_SIZE;
    ctx->ih->metadata.metadata_size = sizeof(record_metadata_t);
    ctx->ih->metadata.revision = SECURESTORE_REVISION;
    if (flags & KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG) {
        get_rand_128((rng_128_t *)&ctx->ih->metadata.iv);

        uint8_t encrypt_key[DERIVED_KEY_SIZE] = {0};
        uint8_t derive_key[DERIVED_KEY_SIZE] = {0};
        memset(ctx->scratch_buf, 0, SCRATCH_BUF_SIZE);
        strcpy((char *)ctx->scratch_buf, ENCRYPT_PREFIX);
        strncat((char *)ctx->scratch_buf, key, SCRATCH_BUF_SIZE - strlen(ENCRYPT_PREFIX) - 1);
        int retk = create_derive_key(ctx, ctx->scratch_buf, SCRATCH_BUF_SIZE, encrypt_key,
                                     sizeof(encrypt_key), derive_key, sizeof(derive_key));
        if (retk) {
            ret = retk;
            goto fail;
        }

        ctx->ih->gcm_ctx = calloc(1, sizeof(mbedtls_gcm_context));
        os_ret = gcm_init_and_starts(ctx, ctx->ih->gcm_ctx, ctx->ih->metadata.iv, IV_SIZE,
                                     derive_key, 128, key, strlen(key), MBEDTLS_GCM_ENCRYPT);
        mbedtls_platform_zeroize(encrypt_key, sizeof(encrypt_key));
        mbedtls_platform_zeroize(derive_key, sizeof(derive_key));

        if (os_ret) {
            ret = KVSTORE_ERROR_FAILED_OPERATION;
            goto fail;
        }
        enc_started = true;
    } else {
        memset(ctx->ih->metadata.iv, 0, IV_SIZE);
    }

    ctx->ih->offset_in_data = 0;
    ctx->ih->key = 0;

    ret = underlying_kvs->set_start(underlying_kvs, handle, key,
                                    sizeof(record_metadata_t) + final_data_size + GCM_TAG_SIZE,
                                    flags & ~SECURITY_FLAGS);
    if (ret) {
        goto fail;
    }
    ret = underlying_kvs->set_add_data(underlying_kvs, handle, &ctx->ih->metadata,
                                       sizeof(record_metadata_t));
    if (ret) {
        goto fail;
    }
    goto end;

fail:
    if (enc_started && ctx->ih->gcm_ctx) {
        mbedtls_gcm_free(ctx->ih->gcm_ctx);
        free(ctx->ih->gcm_ctx);
        ctx->ih->gcm_ctx = NULL;
    }
    ctx->ih->metadata.metadata_size = 0;
    // mutex.unlock()

end:
    return ret;
}

static int set_add_data(kvs_t *kvs, kvs_inc_set_handle_t *handle, const void *value, size_t size) {
    (void)value;
    (void)size;
    int os_ret;
    int ret = KVSTORE_SUCCESS;
    const uint8_t *src_ptr;
    kvs_securekvs_context_t *ctx = kvs->context;

    // if (handle != ctx->ih)
    //     return KVSTORE_ERROR_INVALID_ARGUMENT;
    if (!value && size)
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    if (!ctx->ih->metadata.metadata_size)
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    if (ctx->ih->offset_in_data + size > ctx->ih->metadata.data_size) {
        ret = KVSTORE_ERROR_INVALID_SIZE;
        goto end;
    }

    src_ptr = (const uint8_t *)value;
    while (size) {
        uint32_t chunk_size;
        const uint8_t *dst_ptr;
        if (ctx->ih->metadata.create_flags & KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG) {
            chunk_size = MIN((uint32_t)size, SCRATCH_BUF_SIZE);
            dst_ptr = ctx->scratch_buf;
            os_ret = gcm_update_chunk(ctx->ih->gcm_ctx, src_ptr, (uint8_t *)dst_ptr, chunk_size);
            if (os_ret) {
                ret = KVSTORE_ERROR_FAILED_OPERATION;
                goto fail;
            }
        } else {
            chunk_size = size;
            dst_ptr = (const uint8_t *)value;
        }

        ret = ctx->underlying_kvs->set_add_data(ctx->underlying_kvs, handle, dst_ptr, chunk_size);
        if (ret)
            goto fail;
        size -= chunk_size;
        src_ptr += chunk_size;
        ctx->ih->offset_in_data += chunk_size;
    }
    goto end;

fail:
    if (ctx->ih->key) {
        // free(ctx->ih->key);
        ctx->ih->key = NULL;
    }
    if (ctx->ih->gcm_ctx) {
        mbedtls_gcm_free(ctx->ih->gcm_ctx);
        free(ctx->ih->gcm_ctx);
        ctx->ih->gcm_ctx = NULL;
    }

    ctx->ih->metadata.metadata_size = 0;
    // mutex.unlock();

end:
    return ret;
}

static int set_add_finalize(kvs_t *kvs, kvs_inc_set_handle_t *handle) {
    int os_ret;
    int ret = KVSTORE_SUCCESS;
    uint8_t tag_buf[GCM_TAG_SIZE] = {0};

    kvs_securekvs_context_t *ctx = kvs->context;

    // if (handle != ctx->ih)
    //     return KVSTORE_ERROR_INVALID_ARGUMENT;
    if (!ctx->ih->metadata.metadata_size)
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    if (ctx->ih->offset_in_data != ctx->ih->metadata.data_size - GCM_TAG_SIZE) {
        ret = KVSTORE_ERROR_FAILED_OPERATION;
        goto end;
    }

    if (ctx->ih->metadata.create_flags & KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG && ctx->ih->gcm_ctx) {
        os_ret = gcm_finish_and_tag(ctx->ih->gcm_ctx, tag_buf, GCM_TAG_SIZE);
        if (os_ret) {
            ret = KVSTORE_ERROR_FAILED_OPERATION;
            goto end;
        }
    } else {
        memset(tag_buf, 0, GCM_TAG_SIZE);
    }

    kvs_t *underlying_kvs = ctx->underlying_kvs;
    ret = underlying_kvs->set_add_data(underlying_kvs, handle, tag_buf, GCM_TAG_SIZE);
    if (ret)
        goto end;
    ret = underlying_kvs->set_finalize(underlying_kvs, handle);
    if (ret)
        goto end;

end:
    ctx->ih->metadata.metadata_size = 0;
    if (ctx->ih->gcm_ctx) {
        mbedtls_gcm_free(ctx->ih->gcm_ctx);
        free(ctx->ih->gcm_ctx);
        ctx->ih->gcm_ctx = NULL;
    }
    // mutex.unlock();
    return ret;
}

static int do_get(kvs_t *kvs, const char *key, void *buffer, size_t buffer_size,
                  size_t *actual_size, size_t offset, kvs_info_t *info) {
    int os_ret;
    int ret;
    size_t read_len = 0;
    bool enc_started = false;
    kvs_securekvs_context_t *ctx = kvs->context;

    kvs_t *underlying_kvs = ctx->underlying_kvs;
    ret = underlying_kvs->get(underlying_kvs, key, &ctx->ih->metadata, sizeof(record_metadata_t),
                              &read_len, 0);
    if (ret)
        goto end;
    if ((read_len != sizeof(record_metadata_t)) ||
        (ctx->ih->metadata.metadata_size != sizeof(record_metadata_t))) {
        ret = KVSTORE_ERROR_AUTHENTICATION_FAILED;
        goto end;
    }
    uint32_t flags = ctx->ih->metadata.create_flags;
    flags &= ~KVSTORE_REQUIRE_REPLAY_PROTECTION_FLAG;

    if (flags & KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG) {
        uint8_t encrypt_key[DERIVED_KEY_SIZE] = {0};
        uint8_t derive_key[DERIVED_KEY_SIZE] = {0};
        memset(ctx->scratch_buf, 0, SCRATCH_BUF_SIZE);
        strcpy((char *)ctx->scratch_buf, ENCRYPT_PREFIX);
        strncat((char *)ctx->scratch_buf, key, SCRATCH_BUF_SIZE - strlen(ENCRYPT_PREFIX) - 1);
        int retk = create_derive_key(ctx, ctx->scratch_buf, SCRATCH_BUF_SIZE, encrypt_key,
                                     sizeof(encrypt_key), derive_key, sizeof(derive_key));
        if (retk) {
            ret = retk;
            goto end;
        }

        ctx->ih->gcm_ctx = calloc(1, sizeof(mbedtls_gcm_context));
        os_ret = gcm_init_and_starts(ctx, ctx->ih->gcm_ctx, ctx->ih->metadata.iv, IV_SIZE,
                                     derive_key, 128, key, strlen(key), MBEDTLS_GCM_DECRYPT);
        mbedtls_platform_zeroize(encrypt_key, sizeof(encrypt_key));
        mbedtls_platform_zeroize(derive_key, sizeof(derive_key));
        if (os_ret) {
            ret = KVSTORE_ERROR_FAILED_OPERATION;
            goto end;
        }
        enc_started = true;
    }

    uint32_t data_size = ctx->ih->metadata.data_size - GCM_TAG_SIZE;
    uint32_t actual_data_size = MIN((uint32_t)buffer_size, data_size - offset);
    uint32_t current_offset = 0;
    uint32_t chunk_size;
    memset(ctx->scratch_buf, 0, SCRATCH_BUF_SIZE);
    while (data_size) {
        if ((current_offset >= offset) && (current_offset < actual_data_size)) {
            chunk_size = MIN(SCRATCH_BUF_SIZE, actual_data_size - current_offset);
        } else {
            if (current_offset < offset) {
                chunk_size = MIN(SCRATCH_BUF_SIZE, offset - current_offset);
            } else {
                chunk_size = MIN(SCRATCH_BUF_SIZE, data_size);
            }
        }

        ret = underlying_kvs->get(underlying_kvs, key, ctx->scratch_buf, chunk_size, 0,
                                  ctx->ih->metadata.metadata_size + current_offset);
        if (ret != KVSTORE_SUCCESS) {
            goto end;
        }
        if (flags & KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG) {
            // NOTE: Needed at delete time, but is the MAC calculated?
            if (buffer_size > 0) {
                os_ret = gcm_update_chunk(ctx->ih->gcm_ctx, ctx->scratch_buf, buffer + current_offset,
                                          chunk_size);
            } else {
                os_ret = 0;
            }

            if (os_ret) {
                ret = KVSTORE_ERROR_FAILED_OPERATION;
                goto end;
            }
        }
        current_offset += chunk_size;
        data_size -= chunk_size;
    }
    if (actual_size)
        *actual_size = actual_data_size;

    uint8_t read_tag[GCM_TAG_SIZE];
    ret = underlying_kvs->get(
        underlying_kvs, key, read_tag, GCM_TAG_SIZE, 0,
        ctx->ih->metadata.metadata_size + ctx->ih->metadata.data_size - GCM_TAG_SIZE);
    if (ret) {
        goto end;
    }
    if (flags & KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG && ctx->ih->gcm_ctx) {
        os_ret = gcm_finish_and_check_tag(ctx->ih->gcm_ctx, read_tag, GCM_TAG_SIZE);
        if (os_ret) {
            ret = KVSTORE_ERROR_AUTHENTICATION_FAILED;
            goto end;
        }
    } else {
        ;
    }

    if (info) {
        info->flags = ctx->ih->metadata.create_flags;
        info->size = ctx->ih->metadata.data_size - GCM_TAG_SIZE;
    }

end:
    ctx->ih->metadata.metadata_size = 0;
    if (enc_started && ctx->ih->gcm_ctx) {
        mbedtls_gcm_free(ctx->ih->gcm_ctx);
        free(ctx->ih->gcm_ctx);
        ctx->ih->gcm_ctx = NULL;
    }
    return ret;
}

static int _set(kvs_t *kvs, const char *key, const void *value, size_t size, uint32_t flags) {
    int ret;
    kvs_inc_set_handle_t handle;

    if (!is_valid_key(key))
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    flags |= KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG;

    ret = set_start(kvs, &handle, key, size, flags);
    if (ret) {
        return ret;
    }
    ret = set_add_data(kvs, &handle, value, size);
    if (ret) {
        return ret;
    }
    ret = set_add_finalize(kvs, &handle);
    if (ret) {
        return ret;
    }
    return ret;
}

static int _get(kvs_t *kvs, const char *key, void *buffer, size_t buffer_size, size_t *actual_size,
                size_t offset) {
    // mutex.lock();
    if (!is_valid_key(key))
        return KVSTORE_ERROR_INVALID_ARGUMENT;

    int ret = do_get(kvs, key, buffer, buffer_size, actual_size, offset, NULL);
    // mutex.unlock();
    return ret;
}

static int _delete(kvs_t *kvs, const char *key) {
    kvs_info_t info;

    // mutex.lock()
    if (!is_valid_key(key))
        return KVSTORE_ERROR_INVALID_ARGUMENT;

    int ret = do_get(kvs, key, NULL, 0, NULL, 0, &info);
    if ((ret != KVSTORE_SUCCESS) && (ret != KVSTORE_ERROR_AUTHENTICATION_FAILED)) {
        ret = KVSTORE_ERROR_WRITE_PROTECTED;
        goto end;
    }

    kvs_securekvs_context_t *ctx = kvs->context;
    kvs_t *underlying_kvs = ctx->underlying_kvs;
    ret = underlying_kvs->delete(underlying_kvs, key);
    if (ret)
        goto end;
    ret = KVSTORE_SUCCESS;

end:
    // mutex.unlock()
    return ret;
}

kvs_t *kvs_securekvs_create(kvs_t *underlying_kvs, int (*secretkey_loader)(uint8_t *key)) {
    kvs_t *kvs = calloc(1, sizeof(kvs_t));
    kvs->context = calloc(1, sizeof(kvs_securekvs_context_t));
    kvs_securekvs_context_t *ctx = kvs->context;

    ctx->underlying_kvs = underlying_kvs;
    ctx->secretkey_loader = secretkey_loader;
    kvs->set = _set;
    kvs->get = _get;
    kvs->delete = _delete;

    // init
    // mutex.lock()

    ctx->scratch_buf = calloc(1, SCRATCH_BUF_SIZE);
    ctx->ih = calloc(1, sizeof(inc_set_handle_t));
    ctx->ih->underlying_handle = calloc(1, underlying_kvs->handle_size);

    // int ret = ctx->underlying_kvs->init();

    kvs->is_initialized = true;
    // mutex.unlock()
    return kvs;
}

void kvs_securekvs_free(kvs_t *kvs) {
    // kvs_securekvs_context_t *ctx = kvs->context;
    free(kvs->context);
    free(kvs);
}
