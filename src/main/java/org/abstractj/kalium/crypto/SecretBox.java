/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.removeZeros;

public class SecretBox {

    private byte[] key;

    public SecretBox(byte[] key) {
        this.key = key;
        checkLength(key, CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES);
    }
    
    public SecretBox()
    {
    }

    public SecretBox(String key, Encoder encoder) {
        this(encoder.decode(key));
    }

    public byte[] encrypt(byte[] nonce, byte[] message) {
        checkLength(nonce, CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES);
        byte[] msg = Util.prependZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES, message);
        byte[] ct = Util.zeros(msg.length);
        isValid(sodium().crypto_secretbox_xsalsa20poly1305(ct, msg, msg.length,
                nonce, key), "Encryption failed");
        return removeZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES, ct);
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        checkLength(nonce, CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES);
        byte[] ct = Util.prependZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES, ciphertext);
        byte[] message = Util.zeros(ct.length);
        isValid(sodium().crypto_secretbox_xsalsa20poly1305_open(message, ct,
                ct.length, nonce, key), "Decryption failed. Ciphertext failed verification");
        return removeZeros(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES, message);
    }
    
    /**
     * Encrypt a message. It implements libsodium's crypto_secretbox_easy() function.
     * @param key    crypto_secretbox_KEYBYTES of Encryption key
     * @param nonce  crypto_secretbox_NONCEBYTES of Nonce
     * @param message Message to encrypt
     * @author muquit@muquitcom Oct-02-2016
     * @return encrypted bytes
     * @see also <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">Secret-key authenticated encryption</a>
     */
    public byte[] encryptSecretBoxEasy(byte[] key, byte[] nonce, byte[] message)
    {
    	checkLength(key,sodium().crypto_box_secretkeybytes());
    	checkLength(nonce,sodium().crypto_box_noncebytes());
    	byte[] ct = new byte[message.length + sodium().crypto_box_macbytes()];
    	int rc = sodium().crypto_secretbox_easy(ct, message, message.length, nonce, key);
    	isValid(rc,"Encription failed");
    	return ct;
    }
    
    /**
     * Decrypt an encrypted message encrypted with encryptetSecretBoxEasy(). 
     * It implements libsodium's crypto_secretbox_open_easy() function
     * @param key
     * @param ciphertext
     * @author muquit@muquit.com  Oct-02-2016 first cut
     * @return decrypted bytes 
     * @see also <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">Secret-key authenticated encryption</a>
     */
    public byte[] decryptSecretBoxEeasy(byte[] key, byte[] nonce, byte[] ciphertext)
    {
    	checkLength(key,sodium().crypto_box_secretkeybytes());
    	checkLength(nonce,sodium().crypto_box_noncebytes());
    	byte[] decrypted = new byte[ciphertext.length - sodium().crypto_box_macbytes()];
    	int rc = sodium().crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext.length, nonce, key);
    	isValid(rc,"Decryption failed");
    	return decrypted;
    }
}
