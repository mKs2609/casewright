package com.securityanalyst.gateway.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/** Plain unit test: no Spring, no database. */
class BaselineCipherTest {

    private static final byte[] BASELINE = "{\"usualCountries\":[\"IN\"],\"homeCity\":\"Bengaluru\"}"
            .getBytes(StandardCharsets.UTF_8);

    private static String randomKey(int bytes) {
        byte[] key = new byte[bytes];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private final BaselineCipher cipher = new BaselineCipher(randomKey(32));

    @Test
    void whatGoesInComesBackOut() {
        byte[] stored = cipher.encrypt(BASELINE, "priya.sharma");

        assertThat(cipher.decrypt(stored, "priya.sharma")).isEqualTo(BASELINE);
    }

    @Test
    void theStoredBytesRevealNothingReadable() {
        String stored = new String(cipher.encrypt(BASELINE, "priya.sharma"), StandardCharsets.ISO_8859_1);

        assertThat(stored).doesNotContain("usualCountries").doesNotContain("Bengaluru").doesNotContain("IN\"");
    }

    @Test
    void encryptingTheSameThingTwiceGivesDifferentBytes() {
        // A fresh random nonce each time: identical baselines cannot be spotted in the table.
        assertThat(cipher.encrypt(BASELINE, "priya.sharma")).isNotEqualTo(cipher.encrypt(BASELINE, "priya.sharma"));
    }

    @Test
    void changingAnySingleStoredByteIsDetected() {
        byte[] stored = cipher.encrypt(BASELINE, "priya.sharma");
        for (int i = 1; i < stored.length; i++) {
            byte[] altered = stored.clone();
            altered[i] ^= 0x01;
            assertThatThrownBy(() -> cipher.decrypt(altered, "priya.sharma")).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void aBaselineMovedToAnotherPersonsRowCannotBeRead() {
        byte[] priyas = cipher.encrypt(BASELINE, "priya.sharma");

        assertThatThrownBy(() -> cipher.decrypt(priyas, "arjun.mehta"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("wrong key, wrong row, or the data was altered");
    }

    @Test
    void aDifferentKeyCannotRead() {
        byte[] stored = cipher.encrypt(BASELINE, "priya.sharma");
        BaselineCipher otherKey = new BaselineCipher(randomKey(32));

        assertThatThrownBy(() -> otherKey.decrypt(stored, "priya.sharma")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void onlyA32ByteBase64KeyIsAccepted() {
        assertThatThrownBy(() -> new BaselineCipher(randomKey(16))).hasMessageContaining("32 random bytes");
        assertThatThrownBy(() -> new BaselineCipher("not base64 at all!")).hasMessageContaining("not valid Base64");
    }
}
