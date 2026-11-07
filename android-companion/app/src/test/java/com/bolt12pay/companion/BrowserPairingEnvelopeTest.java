package com.bolt12pay.companion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;

public final class BrowserPairingEnvelopeTest {
    private static final byte[] INFO =
            "bolt12-pay/browser-action/v1".getBytes(StandardCharsets.UTF_8);

    @Test
    public void encryptsSecretsForTheServerWithoutPuttingThemInTheUrl()
            throws Exception {
        ECParameterSpec parameters = parameters();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(parameters);
        KeyPair server = generator.generateKeyPair();
        String publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(
                encodePoint((ECPublicKey) server.getPublic()));
        String plaintext =
                "{\"operation\":\"pair\",\"pairing_token\":"
                        + "\"super-secret-pairing-token-1234567890\"}";

        String envelope = BrowserPairingEnvelope.encrypt(plaintext, publicKey);

        assertTrue(envelope.matches("[A-Za-z0-9_-]+"));
        assertFalse(envelope.contains("super-secret"));

        byte[] packed = Base64.getUrlDecoder().decode(padBase64(envelope));
        assertEquals(1, packed[0]);
        ECPublicKey ephemeral =
                (ECPublicKey)
                        KeyFactory.getInstance("EC")
                                .generatePublic(
                                        new ECPublicKeySpec(
                                                new ECPoint(
                                                        new BigInteger(
                                                                1,
                                                                Arrays.copyOfRange(
                                                                        packed, 2, 34)),
                                                        new BigInteger(
                                                                1,
                                                                Arrays.copyOfRange(
                                                                        packed, 34, 66))),
                                                parameters));
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(server.getPrivate());
        agreement.doPhase(ephemeral, true);
        byte[] actionKey = hkdf(
                agreement.generateSecret(),
                Arrays.copyOfRange(packed, 66, 82));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(actionKey, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(packed, 82, 94)));
        cipher.updateAAD(INFO);
        String decrypted = new String(
                cipher.doFinal(Arrays.copyOfRange(packed, 94, packed.length)),
                StandardCharsets.UTF_8);

        assertEquals(plaintext, decrypted);
    }

    private static ECParameterSpec parameters() throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] encodePoint(ECPublicKey key) {
        byte[] encoded = new byte[65];
        encoded[0] = 4;
        copyCoordinate(key.getW().getAffineX(), encoded, 1);
        copyCoordinate(key.getW().getAffineY(), encoded, 33);
        return encoded;
    }

    private static void copyCoordinate(BigInteger value, byte[] destination, int offset) {
        byte[] encoded = value.toByteArray();
        int sourceOffset = encoded.length == 33 && encoded[0] == 0 ? 1 : 0;
        int length = encoded.length - sourceOffset;
        System.arraycopy(encoded, sourceOffset, destination, offset + 32 - length, length);
    }

    private static byte[] hkdf(byte[] inputKey, byte[] salt) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] pseudoRandomKey = mac.doFinal(inputKey);
        mac.init(new SecretKeySpec(pseudoRandomKey, "HmacSHA256"));
        mac.update(INFO);
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), 32);
    }

    private static String padBase64(String value) {
        return value + "=".repeat((4 - value.length() % 4) % 4);
    }
}
