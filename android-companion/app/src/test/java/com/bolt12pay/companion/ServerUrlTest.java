package com.bolt12pay.companion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class ServerUrlTest {
    @Test
    public void acceptsOnlyCleanHttpsOrigins() {
        assertEquals("https://pay.example.com", ServerUrl.normalize("https://pay.example.com/"));
        assertEquals("https://pay.example.com:8443", ServerUrl.normalize("https://pay.example.com:8443"));
        assertNull(ServerUrl.normalize("http://pay.example.com"));
        assertNull(ServerUrl.normalize("https://user:secret@pay.example.com"));
        assertNull(ServerUrl.normalize("https://pay.example.com/nested"));
        assertNull(ServerUrl.normalize("https://pay.example.com?invoice=secret"));
    }

    @Test
    public void putsThePaymentTargetInAFragment() {
        String result = ServerUrl.paymentHandoff(
                "https://pay.example.com", "lightning:lno1abcdef123");

        assertEquals(
                "https://pay.example.com/pay-intent#lightning=lno1abcdef123", result);
        assertFalse(result.contains("?"));
    }

    @Test
    public void percentEncodesLightningAddressesInTheFragment() {
        String result = ServerUrl.paymentHandoff(
                "https://pay.example.com", "lightning:tips+nostr@pay.example.com");

        assertEquals(
                "https://pay.example.com/pay-intent#lightning=tips%2Bnostr%40pay.example.com",
                result);
        assertFalse(result.contains("@"));
    }
}
