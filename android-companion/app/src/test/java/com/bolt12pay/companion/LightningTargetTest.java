package com.bolt12pay.companion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class LightningTargetTest {
    @Test
    public void acceptsBolt11AndBolt12LightningUris() {
        assertEquals("lno1abcdef123", LightningTarget.normalize("lightning:lno1abcdef123"));
        assertEquals("lnbc10u1abcdef", LightningTarget.normalize("lightning://lnbc10u1abcdef"));
    }

    @Test
    public void acceptsAmethystBip321Bolt12Uris() {
        assertEquals(
                "lno1abcdef123",
                LightningTarget.normalize("bitcoin:?lno=lno1abcdef123"));
        assertEquals(
                "lno1abcdef123",
                LightningTarget.normalize("bitcoin:?amount=0.1&lno=lno1abcdef123"));
        assertEquals(
                "lnbc10u1abcdef",
                LightningTarget.normalize("bitcoin:?lightning=lnbc10u1abcdef"));
        assertEquals(
                "lno1abcdef123",
                LightningTarget.normalize("bitcoin:?lno=lno1abcdef%31%32%33"));
    }

    @Test
    public void rejectsUnsupportedOrAmbiguousTargets() {
        assertNull(LightningTarget.normalize("lightning:lnurl1abcdef"));
        assertNull(LightningTarget.normalize("lightning:lno1abc?amount=1"));
        assertNull(LightningTarget.normalize("https://example.com"));
        assertNull(LightningTarget.normalize("lNo1MixedCase"));
        assertNull(LightningTarget.normalize("bitcoin:bc1qexample"));
        assertNull(LightningTarget.normalize("bitcoin:?amount=0.1"));
        assertNull(LightningTarget.normalize("bitcoin:?lno=lnurl1abcdef"));
        assertNull(
                LightningTarget.normalize(
                        "bitcoin:?lno=lno1abcdef123&lightning=lnbc10u1abcdef"));
        assertNull(LightningTarget.normalize("bitcoin:?lno=lno1abc%ZZ"));
    }
}
