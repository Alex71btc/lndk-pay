package com.bolt12pay.companion;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
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

final class BrowserPairingEnvelope {
    private static final byte VERSION = 1;
    private static final byte[] INFO =
            "bolt12-pay/browser-action/v1".getBytes(StandardCharsets.UTF_8);
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int COORDINATE_BYTES = 32;

    private BrowserPairingEnvelope() {}

    static String encrypt(String payloadJson, String vapidPublicKey)
            throws GeneralSecurityException {
        return encrypt(payloadJson, vapidPublicKey, new SecureRandom());
    }

    static String encrypt(
            String payloadJson,
            String vapidPublicKey,
            SecureRandom random)
            throws GeneralSecurityException {
        if (payloadJson == null || payloadJson.isEmpty() || random == null) {
            throw new GeneralSecurityException("Missing browser pairing data");
        }

        byte[] serverPoint;
        try {
            serverPoint = Base64.getUrlDecoder().decode(padBase64(vapidPublicKey));
        } catch (IllegalArgumentException error) {
            throw new GeneralSecurityException("Invalid server encryption key", error);
        }
        if (serverPoint.length != 65 || serverPoint[0] != 4) {
            throw new GeneralSecurityException("Invalid server encryption key");
        }

        ECParameterSpec parameters = p256Parameters();
        ECPoint serverCoordinates =
                new ECPoint(
                        new BigInteger(1, Arrays.copyOfRange(serverPoint, 1, 33)),
                        new BigInteger(1, Arrays.copyOfRange(serverPoint, 33, 65)));
        ECPublicKey serverKey =
                (ECPublicKey)
                        KeyFactory.getInstance("EC")
                                .generatePublic(
                                        new ECPublicKeySpec(serverCoordinates, parameters));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(parameters, random);
        KeyPair ephemeral = generator.generateKeyPair();

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(ephemeral.getPrivate());
        agreement.doPhase(serverKey, true);
        byte[] sharedSecret = agreement.generateSecret();

        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(salt);
        random.nextBytes(nonce);
        byte[] actionKey = hkdfSha256(sharedSecret, salt, INFO, 32);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(actionKey, "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(INFO);
        byte[] ciphertext = cipher.doFinal(
                payloadJson.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream packed = new ByteArrayOutputStream();
        packed.write(VERSION);
        byte[] ephemeralPoint = encodePoint((ECPublicKey) ephemeral.getPublic());
        packed.write(ephemeralPoint, 0, ephemeralPoint.length);
        packed.write(salt, 0, salt.length);
        packed.write(nonce, 0, nonce.length);
        packed.write(ciphertext, 0, ciphertext.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(packed.toByteArray());
    }

    private static ECParameterSpec p256Parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] encodePoint(ECPublicKey publicKey)
            throws GeneralSecurityException {
        byte[] x = unsignedCoordinate(publicKey.getW().getAffineX());
        byte[] y = unsignedCoordinate(publicKey.getW().getAffineY());
        byte[] encoded = new byte[65];
        encoded[0] = 4;
        System.arraycopy(x, 0, encoded, 1, x.length);
        System.arraycopy(y, 0, encoded, 33, y.length);
        return encoded;
    }

    private static byte[] unsignedCoordinate(BigInteger value)
            throws GeneralSecurityException {
        byte[] encoded = value.toByteArray();
        if (encoded.length == COORDINATE_BYTES) return encoded;
        if (encoded.length == COORDINATE_BYTES + 1 && encoded[0] == 0) {
            return Arrays.copyOfRange(encoded, 1, encoded.length);
        }
        if (encoded.length > COORDINATE_BYTES) {
            throw new GeneralSecurityException("Invalid EC coordinate");
        }
        byte[] padded = new byte[COORDINATE_BYTES];
        System.arraycopy(
                encoded,
                0,
                padded,
                COORDINATE_BYTES - encoded.length,
                encoded.length);
        return padded;
    }

    private static byte[] hkdfSha256(
            byte[] inputKey,
            byte[] salt,
            byte[] info,
            int length)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] pseudoRandomKey = mac.doFinal(inputKey);

        mac.init(new SecretKeySpec(pseudoRandomKey, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        byte[] block = mac.doFinal();
        return Arrays.copyOf(block, length);
    }

    private static String padBase64(String value) {
        if (value == null) return "";
        int padding = (4 - value.length() % 4) % 4;
        return value + "=".repeat(padding);
    }
}
