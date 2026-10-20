package com.securityanalyst.gateway.identity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Encrypts baselines before they are stored, and decrypts them after they are read
 * (ADR-37). The database only ever holds unreadable bytes; the key comes from
 * BASELINE_ENCRYPTION_KEY and never goes near the database.
 *
 * AES-256-GCM is "authenticated encryption": besides hiding the content, it detects any
 * change to the stored bytes. Decryption fails loudly instead of returning altered data.
 *
 * Stored format: [1 byte version][12 bytes nonce][ciphertext + 16-byte tag]
 * - The version byte lets the format or key change later without guessing.
 * - The nonce is random and new for every encryption. Reusing a nonce with the same key
 *   would break GCM's security, so it is never chosen by hand.
 * - The identity is bound in as "associated data": it is not stored in the ciphertext,
 *   but decryption only works for the same identity. So someone who can write to the
 *   table cannot swap one person's baseline onto another person's row.
 */
@Component
public class BaselineCipher {

    private static final byte VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public BaselineCipher(@Value("${security.baseline.encryption-key}") String base64Key) {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            // Deliberately not chained: the original message quotes part of the key.
            throw new IllegalStateException("BASELINE_ENCRYPTION_KEY is not valid Base64");
        }
        if (raw.length != 32) {
            throw new IllegalStateException("BASELINE_ENCRYPTION_KEY must be 32 random bytes (AES-256), Base64-encoded");
        }
        this.key = new SecretKeySpec(raw, "AES");
        Arrays.fill(raw, (byte) 0);
    }

    public byte[] encrypt(byte[] plaintext, String identity) {
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(associatedData(identity));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(1 + NONCE_BYTES + ciphertext.length)
                    .put(VERSION).put(nonce).put(ciphertext).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Baseline encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] stored, String identity) {
        if (stored.length < 1 + NONCE_BYTES + TAG_BITS / 8 || stored[0] != VERSION) {
            throw new IllegalStateException("Stored baseline for '" + identity + "' is not in a known format");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, stored, 1, NONCE_BYTES));
            cipher.updateAAD(associatedData(identity));
            return cipher.doFinal(stored, 1 + NONCE_BYTES, stored.length - 1 - NONCE_BYTES);
        } catch (AEADBadTagException e) {
            throw new IllegalStateException("Stored baseline for '" + identity
                    + "' could not be decrypted: wrong key, wrong row, or the data was altered");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Baseline decryption failed", e);
        }
    }

    private static byte[] associatedData(String identity) {
        return ("monitored_identities:" + identity).getBytes(StandardCharsets.UTF_8);
    }
}
