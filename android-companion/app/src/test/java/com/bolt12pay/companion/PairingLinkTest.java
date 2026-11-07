package com.bolt12pay.companion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class PairingLinkTest {
    private static final String VAPID =
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String TOKEN =
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    @Test
    public void acceptsStrictPairingLink() {
        String server = "https://pay.example.com:8443";
        PairingLink parsed =
                PairingLink.parse(
                        "bolt12pay://pair?server="
                                + URLEncoder.encode(server, StandardCharsets.UTF_8)
                                + "&token="
                                + TOKEN
                                + "&vapid="
                                + VAPID);

        assertEquals(server, parsed.serverUrl);
        assertEquals(TOKEN, parsed.pairingToken);
        assertEquals(VAPID, parsed.vapidPublicKey);
    }

    @Test
    public void recognizesExplicitBrowserPairingMode() {
        PairingLink parsed = PairingLink.parse(
                "bolt12pay://pair?server=https%3A%2F%2Fumbrel.local%3A8091"
                        + "&token=" + TOKEN
                        + "&vapid=" + VAPID
                        + "&mode=browser");

        assertEquals("https://umbrel.local:8091", parsed.serverUrl);
        org.junit.Assert.assertTrue(parsed.browserPairing);
    }

    @Test
    public void rejectsUnknownPairingMode() {
        assertNull(PairingLink.parse(
                "bolt12pay://pair?server=https%3A%2F%2Fpay.example.com"
                        + "&token=" + TOKEN
                        + "&vapid=" + VAPID
                        + "&mode=unsafe"));
    }

    @Test
    public void rejectsInsecureOrMalformedPairingData() {
        assertNull(PairingLink.parse("bolt12pay://pair?server=http://pay.example.com"));
        assertNull(
                PairingLink.parse(
                        "bolt12pay://pair?server=https%3A%2F%2Fpay.example.com%2Fadmin"
                                + "&token="
                                + TOKEN
                                + "&vapid="
                                + VAPID));
        assertNull(
                PairingLink.parse(
                        "bolt12pay://pair?server=https%3A%2F%2Fpay.example.com"
                                + "&token=short&vapid="
                                + VAPID));
    }
}
