/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium;

import jnr.ffi.LibraryLoader;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.size_t;
import jnr.ffi.types.u_int64_t;

public class NaCl {

    public static Sodium sodium() {
        Sodium sodium = SingletonHolder.SODIUM_INSTANCE;
        checkVersion(sodium);
        return sodium;
    }

    private static final String LIBRARY_NAME = "sodium";

    private static final class SingletonHolder {
        public static final Sodium SODIUM_INSTANCE =
                LibraryLoader.create(Sodium.class)
                        .search("/usr/local/lib")
                        .search("/opt/local/lib")
                        .search("lib")
                        .load(LIBRARY_NAME);

    }

    public static final Integer[] MIN_SUPPORTED_VERSION =
            new Integer[] { 1, 0, 3 };

    private static boolean versionSupported = false;

    private static final void checkVersion(Sodium lib) {
        if (!versionSupported) {
            String[] version = lib.sodium_version_string().split("\\.");
            versionSupported = version.length >= 3 &&
                MIN_SUPPORTED_VERSION[0] <= new Integer(version[0]) &&
                MIN_SUPPORTED_VERSION[1] <= new Integer(version[1]) &&
                MIN_SUPPORTED_VERSION[2] <= new Integer(version[2]);
        }
        if (!versionSupported) {
            String message = String.format("Unsupported libsodium version: %s. Please update",
                                        lib.sodium_version_string());
            throw new UnsupportedOperationException(message);
        }
    }

    private NaCl() {
    }

    public interface Sodium {

        int sodium_library_version_major();
        int sodium_library_version_minor();
        
        int crypto_pwhash_alg_argon2i13();
        int crypto_pwhash_alg_default();
        @size_t int crypto_pwhash_saltbytes();
        @size_t int crypto_pwhash_strbytes();
        @size_t int crypto_pwhash_opslimit_interactive();
        @size_t int crypto_pwhash_memlimit_interactive();

        /* from crypto_box.h */
        @size_t int crypto_box_seedbytes();
        @size_t int crypto_box_publickeybytes();
        @size_t int crypto_box_secretkeybytes();
        @size_t int crypto_box_noncebytes();
        @size_t int crypto_box_macbytes();        
        

        /**
         * This function isn't thread safe. Be sure to call it once, and before
         * performing other operations.
         *
         * Check libsodium's documentation for more info.
         */
        int sodium_init();

        String sodium_version_string();

        // ---------------------------------------------------------------------
        // Generating Random Data

        void randombytes(@Out byte[] buffer, @In @u_int64_t int size);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authenticated encryption

        /**
         * @deprecated use CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES
         */
        @Deprecated
        int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;

        /**
         * @deprecated use CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES
         */
        @Deprecated
        int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES = 32;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES = 24;

        int crypto_secretbox_xsalsa20poly1305(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_xsalsa20poly1305_open(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        
        /**
         * 
         * @param ct
         * @param msg
         * @param msg_len
         * @param nonce
         * @param key
         * @author muquit@muquit.com Oct-02-2016 first cut
         * @return 0 on success
         */
        int crypto_secretbox_easy(
        		@Out byte[] ct, @In byte[] msg, @In @u_int64_t int msg_len,
        		@In byte[] nonce, @In byte[] key
        		);
        
        /**
         * 
         * @param decrypted
         * @param ct
         * @param ct_len
         * @param nonce
         * @param key
         * @author muquit@muquit.com Oct-02-2016 first cut
         * @return 0 on success
         */
        int crypto_secretbox_open_easy(
        		@Out byte[] decrypted, @In byte[] ct, @In @u_int64_t int ct_len,
        		@In byte[] nonce, @In byte[] key
        		);
        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authentication

        /**
         * @deprecated use CRYPTO_AUTH_HMACSHA512256_BYTESS
         */
        @Deprecated
        int HMACSHA512256_BYTES = 32;

        /**
         * @deprecated use CRYPTO_AUTH_HMACSHA512256_KEYBYTESS
         */
        @Deprecated
        int HMACSHA512256_KEYBYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_BYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32;

        int crypto_auth_hmacsha512256(
                @Out byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        int crypto_auth_hmacsha512256_verify(
                @In byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: AEAD

        // TODO

        // ---------------------------------------------------------------------
        // Public-key cryptography: Authenticated encryption

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES
         */
        @Deprecated
        int PUBLICKEY_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTESS
         */
        @Deprecated
        int SECRETKEY_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES
         */
        @Deprecated
        int NONCE_BYTES = 24;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTESS
         */
        @Deprecated
        int ZERO_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES
         */
        @Deprecated
        int BOXZERO_BYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES -
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES = 24;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32;

        int crypto_box_curve25519xsalsa20poly1305_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey);

        int crypto_box_curve25519xsalsa20poly1305_beforenm(
                @Out byte[] sharedkey, @In byte[] publicKey,
                @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305_afternm(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        int crypto_box_curve25519xsalsa20poly1305_open(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305_open_afternm(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        
        /**
         * 
         * @param ct
         * @param msg
         * @param msg_len
         * @param nonce
         * @param publicKey
         * @param privateKey
         * @author muquit@muquit.com Oct-03-2016 first cut
         * @return 0 on success
         */
        int crypto_box_easy(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int msg_len,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey
                );
        
        /**
         * 
         * @param decrypted
         * @param ct
         * @param ct_len
         * @param nonce
         * @param publicKey
         * @param privateKey
         * @author muquit@muquit.com Oct-03-2016 first cut
         * @return 0 on success
         */
        int cryto_box_open_easy(
                @Out byte[] decrypted, @In byte[] ct, @In @u_int64_t int ct_len,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey
                );
        // ---------------------------------------------------------------------
        // Public-key cryptography: Public-key signatures

        /**
         * @deprecated use the documented CRYPTO_SIGN_ED25519_BYTES.
         */
        @Deprecated
        int SIGNATURE_BYTES = 64;

        int CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32;

        int CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64;

        int CRYPTO_SIGN_ED25519_BYTES = 64;

        int crypto_sign_ed25519_seed_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_ed25519(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] message, @In @u_int64_t int length,
                @In byte[] secretKey);

        int crypto_sign_ed25519_open(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] sigAndMsg, @In @u_int64_t int length,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Sealed boxes

        int CRYPTO_BOX_SEALBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES +
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;

        int crypto_box_seal(
                @Out byte[] ct, @In byte[] message, @In @u_int64_t int length,
                @In byte[] publicKey);

        int crypto_box_seal_open(
                @Out byte[] message, @In byte[] c, @In @u_int64_t int length,
                @In byte[] publicKey, @In byte[] privateKey);

        // ---------------------------------------------------------------------
        // Hashing: Generic hashing

        /**
         * @deprecated use CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX. Note that
         * the Libsodium standard value is '32' and not '64' as defined here.
         */
        @Deprecated
        int BLAKE2B_OUTBYTES = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX = 64;

        int crypto_generichash_blake2b(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen);

        int crypto_generichash_blake2b_salt_personal(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen, @In byte[] salt,
                @In byte[] personal);

        // ---------------------------------------------------------------------
        // Hashing: Short-input hashing

        // TODO

        // ---------------------------------------------------------------------
        // Password hashing

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;


        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;

        int crypto_pwhash_scryptsalsa208sha256(
                @Out byte[] buffer, @In @u_int64_t int outlen,
                @In byte[] passwd,
                @In @u_int64_t int passwdlen, @In byte[] salt,
                @In @u_int64_t long opslimit, @In @u_int64_t long memlimit);

        int crypto_pwhash_scryptsalsa208sha256_str(
                @Out byte[] buffer, @In byte[] passwd,
                @In @u_int64_t int passwdlen, @In @u_int64_t long opslimit,
                @In @u_int64_t long memlimit);

        int crypto_pwhash_scryptsalsa208sha256_str_verify(
                @In byte[] buffer, @In byte[] passwd,
                @In @u_int64_t int passwdlen);

        
        
        /**
         * Derive a brute force resistant key from password hashing using Argon2.
         * It is first introduced in libsodium v1.0.9.
         * 
         * @param key       Derived key bytes returns
         * @param keylen    Length of the key 
         * @param passwd    Password
         * @param passwdlen Length of Password
         * @param salt      Salt bytes. Length is crypto_pwhash_SALTBYTES 
         * @param opslimit  represents a maximum amount of computations to perform. 
         * Raising this number will make the function require more CPU cycles to compute a key
         * @param memlimit  is the maximum amount of RAM that the function will use, in bytes.
         * @param alg       is an identifier for the algorithm to use and should be currently 
         * set to crypto_pwhash_ALG_DEFAULT   
         * @author muquit@muquit.com - Oct-2-2016 first cut
         * @return 0 on success
         * @see <a href="https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html">Ref in libsodium</a>
         * @see <a href="https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf">Argon2 Details2 Details</a>
         */
        int crypto_pwhash(
                @Out byte[] key, @In @u_int64_t int keylen,
                @In byte[] passwd, @In @u_int64_t int passwdlen, 
                @In byte[] salt,
                @In @u_int64_t long opslimit, @In @u_int64_t long memlimit,
                @In @u_int64_t int alg
                );

        // ---------------------------------------------------------------------
        // Advanced: AES256-GCM

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: SHA-2

        /**
         * @deprecated use CRYPTO_HASH_SHA256_BYTES
         */
        int SHA256BYTES = 32;

        /**
         * @deprecated use CRYPTO_HASH_SHA512_BYTES
         */
        int SHA512BYTES = 64;

        int CRYPTO_HASH_SHA256_BYTES = 32;

        int crypto_hash_sha256(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        int CRYPTO_HASH_SHA512_BYTES = 64;

        int crypto_hash_sha512(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        // ---------------------------------------------------------------------
        // Advanced: HMAC-SHA-2

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: One-time authentication

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Diffie-Hellman

        int CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;

        int CRYPTO_SCALARMULT_CURVE25519_BYTES = 32;

        int crypto_scalarmult_curve25519(
                @Out byte[] result, @In byte[] intValue, @In byte[] point);

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: ChaCha20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: Salsa20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: XSalsa20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Ed25519 to Curve25519

    }

    /**
     * This is a Java synchronized wrapper around libsodium's init function.
     * LibSodium's init function is not thread-safe.
     *
     * Check libsodium's documentation for more info.
     */
    public static synchronized int init() {
        return sodium().sodium_init();
    }
}
