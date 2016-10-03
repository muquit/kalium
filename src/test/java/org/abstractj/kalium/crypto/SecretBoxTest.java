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

import org.junit.Test;

import java.util.Arrays;

import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.BOX_CIPHERTEXT;
import static org.abstractj.kalium.fixture.TestVectors.BOX_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.BOX_NONCE;
import static org.abstractj.kalium.fixture.TestVectors.SECRET_KEY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SecretBoxTest {

    @Test
    public void testAcceptStrings() throws Exception {
        try {
            new SecretBox(SECRET_KEY, HEX);
        } catch (Exception e) {
            fail("SecretBox should accept strings");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testNullKey() throws Exception {
        byte[] key = null;
        new SecretBox(key);
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testShortKey() throws Exception {
        String key = "hello";
        new SecretBox(key.getBytes());
        fail("Should raise an exception");
    }

    @Test
    public void testEncrypt() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY, HEX);

        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] message = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = HEX.decode(BOX_CIPHERTEXT);

        byte[] result = box.encrypt(nonce, message);
        assertTrue("failed to generate ciphertext", Arrays.equals(result, ciphertext));
    }

    @Test
    public void testDecrypt() throws Exception {

        SecretBox box = new SecretBox(SECRET_KEY, HEX);

        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] expectedMessage = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, expectedMessage);

        byte[] message = box.decrypt(nonce, ciphertext);

        assertTrue("failed to decrypt ciphertext", Arrays.equals(message, expectedMessage));
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptCorruptedCipherText() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY, HEX);
        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] message = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, message);
        ciphertext[23] = ' ';

        box.decrypt(nonce, ciphertext);
        fail("Should raise an exception");
    }
    
    @Test
    public void testEncryptSecretboxEasy()
    {
        SecretBox box = new SecretBox();
        byte[] key = HEX.decode("476d427e2bf7d0bd19b642257711ed6ee965fd0042923a20114788af1e66dbbf");
        byte[] message = HEX.decode("753d936a4d4b668a0b345e81db9582b11d2c4008754beaad4eef28a912c42db1");
        byte[] nonce = HEX.decode("32f2fc22dd1bfac7e91db52b630258b309a6794c50b98a56");
        byte[] cipherText = box.encryptSecretBoxEasy(key,nonce,message);
        String cipherTextHex = HEX.encode(cipherText);
        String expectedCipherTextHex = "252311348e1a06085d6d44105a8391ef531b5b7f0be03f8dabcd7e7d4e0f2a3784cf7ad697c491309b1e3de85f19e58f";
        assertEquals(cipherTextHex,expectedCipherTextHex);
    }
    @Test
    public void testDecryptSecretboxEasy()
    {
        SecretBox box = new SecretBox();
        byte[] key = HEX.decode("476d427e2bf7d0bd19b642257711ed6ee965fd0042923a20114788af1e66dbbf");
        String cipherTextHex = "252311348e1a06085d6d44105a8391ef531b5b7f0be03f8dabcd7e7d4e0f2a3784cf7ad697c491309b1e3de85f19e58f";
        String expectedPlainTextHex = "753d936a4d4b668a0b345e81db9582b11d2c4008754beaad4eef28a912c42db1";
        byte[] cipherText = HEX.decode(cipherTextHex);
        byte[] nonce = HEX.decode("32f2fc22dd1bfac7e91db52b630258b309a6794c50b98a56");
        byte[] plainText = box.decryptSecretBoxEeasy(key,nonce,cipherText);
        String plainTextHex = HEX.encode(plainText);
        assertEquals(plainTextHex, expectedPlainTextHex);
    }
}
