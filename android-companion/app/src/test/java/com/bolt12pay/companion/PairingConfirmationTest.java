package com.bolt12pay.companion;

import static org.junit.Assert.*;

import org.junit.Test;

public final class PairingConfirmationTest {
    private final String pending = "A".repeat(43);
    private final String device = "B".repeat(43);

    @Test
    public void acceptsMatchingPairingToken() {
        assertEquals(
                device,
                PairingConfirmation.verifiedDeviceToken(
                        pending, pending, device));
    }

    @Test
    public void rejectsDifferentPairingToken() {
        assertNull(
                PairingConfirmation.verifiedDeviceToken(
                        pending, "C".repeat(43), device));
    }

    @Test
    public void rejectsMissingPendingPairing() {
        assertNull(
                PairingConfirmation.verifiedDeviceToken(
                        "", pending, device));
    }

    @Test
    public void rejectsMalformedDeviceToken() {
        assertNull(
                PairingConfirmation.verifiedDeviceToken(
                        pending, pending, "invalid token!"));
    }

    @Test
    public void acceptsOnlyTheExpectedPendingBrowserAction() {
        assertTrue(
                PairingConfirmation.verifiedActionNonce(
                        "renew", "renew", pending, pending));
        assertFalse(
                PairingConfirmation.verifiedActionNonce(
                        "revoke", "renew", pending, pending));
        assertFalse(
                PairingConfirmation.verifiedActionNonce(
                        "renew", "renew", pending, "C".repeat(43)));
    }
}
