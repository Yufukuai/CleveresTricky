/*
 * cleverestricky_cbor_cose.h
 *
 * C header for the Rust CBOR/COSE core library.
 * Architecture: Zygisk -> C++ entry (binder_interceptor) -> Rust core
 *
 * SYMBOL VISIBILITY / ANTI-DETECTION
 * -----------------------------------
 * These function names are ONLY visible at link time. They do NOT appear in
 * the final .so because the CMake build uses:
 *   -fvisibility=hidden   (C++ symbols default to hidden)
 *   -s                    (strip all symbol tables)
 *   --exclude-libs,ALL    (prevent re-exporting from static libs)
 * Combined with Rust's release profile (strip = "symbols", lto = true),
 * no Rust symbols leak into the loadable binary. Renaming them would be
 * security-through-obscurity with no real benefit — the linker already
 * removes them from the exported symbol table.
 *
 * BUFFER OWNERSHIP
 * ----------------
 * !! NEVER call free() / delete on a RustBuffer.data pointer !!
 * Rust-allocated memory MUST be returned to Rust via rust_free_buffer().
 * The C/C++ and Rust heaps are separate; calling the wrong deallocator
 * causes undefined behaviour (double-free, heap corruption, crashes).
 */

#ifndef CLEVERESTRICKY_CBOR_COSE_H
#define CLEVERESTRICKY_CBOR_COSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Buffer returned by Rust FFI functions.
 *
 * OWNERSHIP RULE: The caller MUST free this buffer by calling
 * rust_free_buffer(). Do NOT pass buf.data to free() or delete.
 * A null data pointer with len==0 indicates an error or empty result.
 */
typedef struct {
    uint8_t *data;
    size_t len;
} RustBuffer;

/**
 * Free a buffer previously returned by a Rust FFI function.
 * Safe to call with a null/empty buffer. Idempotent for empty buffers.
 *
 * !! This is the ONLY correct way to release a RustBuffer !!
 */
void rust_free_buffer(RustBuffer buf);

/* ==== CBOR Encoding ==== */

/** Encode a CBOR unsigned integer. */
RustBuffer rust_cbor_encode_unsigned(uint64_t value);

/** Encode a CBOR signed integer (positive or negative). */
RustBuffer rust_cbor_encode_int(int64_t value);

/** Encode a CBOR byte string. data may be NULL if len is 0. */
RustBuffer rust_cbor_encode_bytes(const uint8_t *data, size_t len);

/** Encode a CBOR text string (UTF-8). data may be NULL if len is 0. */
RustBuffer rust_cbor_encode_text(const uint8_t *data, size_t len);

/* ==== COSE / RKP Operations ==== */

/**
 * Generate a COSE_Mac0 MACed public key for RKP.
 *
 * @param x_ptr     EC P-256 public key X coordinate bytes.
 * @param x_len     Length of X coordinate (typically 32).
 * @param y_ptr     EC P-256 public key Y coordinate bytes.
 * @param y_len     Length of Y coordinate (typically 32).
 * @param hmac_key_ptr  HMAC-SHA256 key bytes.
 * @param hmac_key_len  Length of HMAC key (typically 32).
 * @return COSE_Mac0 encoded bytes, or empty buffer on error.
 */
RustBuffer rust_generate_maced_public_key(
    const uint8_t *x_ptr, size_t x_len,
    const uint8_t *y_ptr, size_t y_len,
    const uint8_t *hmac_key_ptr, size_t hmac_key_len
);

/**
 * Create a DeviceInfo CBOR map for RKP certificate requests.
 * Pass NULL/0 for any field to use defaults.
 */
RustBuffer rust_create_device_info(
    const uint8_t *brand_ptr, size_t brand_len,
    const uint8_t *manufacturer_ptr, size_t manufacturer_len,
    const uint8_t *product_ptr, size_t product_len,
    const uint8_t *model_ptr, size_t model_len,
    const uint8_t *device_ptr, size_t device_len
);

/**
 * Create a certificate request response for RKP.
 *
 * @param keys_data_ptr     Concatenated MACed key bytes.
 * @param keys_data_len     Total length of concatenated keys.
 * @param keys_offsets_ptr  Array of (keys_count+1) offsets marking key boundaries.
 * @param keys_count        Number of keys.
 * @param challenge_ptr     Server challenge bytes.
 * @param challenge_len     Length of challenge.
 * @param device_info_ptr   CBOR-encoded DeviceInfo bytes.
 * @param device_info_len   Length of DeviceInfo.
 * @return Certificate request response bytes, or empty buffer on error.
 */
RustBuffer rust_create_certificate_request(
    const uint8_t *keys_data_ptr, size_t keys_data_len,
    const size_t *keys_offsets_ptr, size_t keys_count,
    const uint8_t *challenge_ptr, size_t challenge_len,
    const uint8_t *device_info_ptr, size_t device_info_len
);

/**
 * Generate a spoofed Boot Certificate Chain (BCC).
 *
 * Returns a RustBuffer containing the CBOR-encoded BCC array.
 * The caller must free the buffer with `rust_free_buffer`.
 */
RustBuffer rust_generate_spoofed_bcc(void);

/**
 * Generate an advanced KeyMint 4.0 exploitation payload.
 *
 * Returns a RustBuffer containing the simulated exploit payload.
 * The caller must free the buffer with `rust_free_buffer`.
 */
RustBuffer rust_generate_keymint_exploit_payload(void);

/* ==== Fingerprint Cache ==== */

/**
 * Inject fingerprint data (newline-separated) into the in-memory cache.
 * Returns the number of fingerprints parsed, or 0 on error.
 */
size_t rust_fp_inject(const uint8_t *data_ptr, size_t data_len);

/**
 * Fetch fingerprints from a URL into the cache.
 * Pass NULL/0 to use the default Pixel Beta fingerprint URL.
 * Returns the number of fingerprints fetched, or 0 on error.
 */
size_t rust_fp_fetch(const uint8_t *url_ptr, size_t url_len);

/**
 * Look up a cached fingerprint by device codename.
 * Returns the fingerprint string as a RustBuffer (free with rust_free_buffer),
 * or an empty buffer if not found.
 */
RustBuffer rust_fp_get(const uint8_t *device_ptr, size_t device_len);

/** Get the number of fingerprints currently in the cache. */
size_t rust_fp_count(void);

/** Clear the fingerprint cache. */
void rust_fp_clear(void);

/* ==== Utils ==== */

/**
 * Trigger signal to interrupt threads blocked in ioctl.
 * Used during initialization.
 */
void rust_kick_already_blocked_ioctls(void);

/* ==== Race Condition Engine ==== */

/**
 * Start the Multi-Factor Race Condition Engine on the specified core.
 *
 * This spawns a thread pinned to `core_id` that continuously executes
 * the race condition logic (TOCTOU simulation).
 *
 * @param core_id   The CPU core ID to pin the engine thread to.
 */
void rust_start_race_engine(size_t core_id);


/* ==== System Properties ==== */

/**
 * Look up a spoofed property from the thread-safe Rust cache.
 * Returns the property string as a RustBuffer (free with rust_free_buffer),
 * or an empty buffer if not found.
 */
RustBuffer rust_prop_get(const uint8_t *name_ptr, size_t name_len);

/**
 * Set a spoofed property in the thread-safe Rust cache.
 */
void rust_prop_set(const uint8_t *name_ptr, size_t name_len, const uint8_t *value_ptr, size_t value_len);

/* ==== Binder Stream Parser (Rust) ==== */
typedef struct {
    size_t target_ptr_offset;
    size_t cookie_offset;
    size_t code_offset;
    size_t flags_offset;
    size_t sender_pid_offset;
    size_t sender_euid_offset;
    size_t data_size_offset;
    size_t data_ptr_offset;
    size_t transaction_data_size;
    size_t transaction_data_secctx_size;
    bool   valid;
} RustOffsetCacheView;

typedef struct {
    uintptr_t target_ptr;
    uintptr_t cookie;
    uint32_t  code;
    uint32_t  flags;
    int32_t   sender_pid;
    uint32_t  sender_euid;
    uint64_t  data_size;
    uintptr_t data_buffer;
    uint32_t  cmd;
    uintptr_t raw_ptr;
    size_t    raw_size;
    bool      valid;
} RustParsedTransaction;

bool rust_parse_binder_stream(const uint8_t *buffer_ptr,
                              size_t consumed,
                              size_t buffer_size,
                              const RustOffsetCacheView *cache,
                              RustParsedTransaction *out_txns,
                              size_t max_txns,
                              size_t *out_txn_count);



/* ==== Play Integrity Protection ==== */
bool rust_is_integrity_service_descriptor(const uint8_t* desc_ptr, size_t desc_len);
bool rust_is_recall_related_transaction(uint32_t code, const uint8_t* desc_ptr, size_t desc_len);
bool rust_is_integrity_verdict_transaction(uint32_t code, const uint8_t* desc_ptr, size_t desc_len);
bool rust_is_remediation_dialog_intent(const uint8_t* action_ptr, size_t action_len);
void rust_record_token_request(void);
bool rust_is_request_rate_normal(void);

#ifdef __cplusplus
}
#endif

#endif /* CLEVERESTRICKY_CBOR_COSE_H */
