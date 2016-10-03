package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import org.abstractj.kalium.encoders.Encoder;
import static org.abstractj.kalium.crypto.Util.checkLength;

public class Password {

    public Password() {
    }
    public byte[] deriveKey(int length, byte[] passwd, byte[] salt, int opslimit, long memlimit) {
        byte[] buffer = new byte[length];
        sodium().crypto_pwhash_scryptsalsa208sha256(buffer, buffer.length, passwd, passwd.length, salt, opslimit, memlimit);
        return buffer;
    }

    public String hash(byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        byte[] buffer = deriveKey(CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES, passwd, salt, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public String hash(int length, byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        byte[] buffer = deriveKey(length, passwd, salt, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public String hash(byte[] passwd, Encoder encoder, int opslimit, long memlimit) {
        byte[] buffer = new byte[CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES];
        sodium().crypto_pwhash_scryptsalsa208sha256_str(buffer, passwd, passwd.length, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public boolean verify(byte[] hashed_passwd, byte[] passwd) {
        int result = sodium().crypto_pwhash_scryptsalsa208sha256_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }
    
    public int pwhash_algorithm() 
    {
    	int alg = sodium().crypto_pwhash_alg_default();
    	return alg;
    }
    
    /**
     * Derive a key from password using Argon2 password hashing scheme. Argon2 is added in libsodium 1.0.9
     * 
     * @param passwd Password bytes
     * @param salt Salt bytes. Length must be sodium().crypto_pwhash_saltbytes()
     * @author muquit@muquit.com 
     * @return bytes of generated key 
     * @see <a href="https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html">https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html</a>
     */
    public byte[] deriveKeyArgon2(byte[] passwd,byte[] salt)
    {
    	checkLength(salt, sodium().crypto_pwhash_saltbytes());
    	byte[] key = new byte[sodium().crypto_box_seedbytes()];
    	sodium().crypto_pwhash(key, key.length, passwd, passwd.length, salt, 
    			sodium().crypto_pwhash_opslimit_interactive(),
    			sodium().crypto_pwhash_memlimit_interactive(),
    			sodium().crypto_pwhash_alg_argon2i13());
    			
    	return key;
    }

    public void printSodiumLibraryVersion()
    {
        int major = sodium().sodium_library_version_major();
        int minor = sodium().sodium_library_version_minor();
        System.out.println("libsodium version: " + major + "." + minor);
    }
}
