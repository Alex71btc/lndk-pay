package com.bolt12pay.companion;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

final class PairingConfirmation {
    private PairingConfirmation() {}

    static String verifiedDeviceToken(
            String pendingToken,
            String receivedPairingToken,
            String receivedDeviceToken) {

        if (!validToken(pendingToken)
                || !validToken(receivedPairingToken)
                || !validToken(receivedDeviceToken)) {
            return null;
        }

        boolean matches = MessageDigest.isEqual(
                pendingToken.getBytes(StandardCharsets.UTF_8),
                receivedPairingToken.getBytes(StandardCharsets.UTF_8));

        return matches ? receivedDeviceToken : null;
    }

    static boolean verifiedActionNonce(
            String expectedOperation,
            String pendingOperation,
            String pendingNonce,
            String receivedNonce) {
        if (expectedOperation == null
                || !expectedOperation.equals(pendingOperation)
                || !validToken(pendingNonce)
                || !validToken(receivedNonce)) {
            return false;
        }
        return MessageDigest.isEqual(
                pendingNonce.getBytes(StandardCharsets.UTF_8),
                receivedNonce.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean validToken(String value) {
        return value != null
                && value.length() >= 32
                && value.length() <= 200
                && value.matches("[A-Za-z0-9_-]+");
    }
}
