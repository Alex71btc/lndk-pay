package com.bolt12pay.companion;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public final class PushSettingsTest {
    @Test
    public void paymentCommentsDefaultOffAndPersistWhenEnabled() {
        SharedPreferences preferences = inMemoryPreferences();

        PushSettings initial = new PushSettings(preferences);
        assertFalse(initial.showPaymentComments());

        initial.setShowPaymentComments(true);
        PushSettings reopened = new PushSettings(preferences);
        assertTrue(reopened.showPaymentComments());
    }

    @Test
    public void browserPairingPersistsModeAndTracksRenewalAndRevokeActions() {
        PushSettings settings = new PushSettings(inMemoryPreferences());

        settings.savePending(
                "A".repeat(43),
                "B".repeat(87),
                "Pixel Test",
                true);
        assertTrue(settings.isBrowserPairing());
        assertTrue(settings.isPairing());
        assertFalse(settings.hasPendingBrowserAction());

        settings.saveBrowserSubscription(
                "https://push.example/one", "C".repeat(87), "D".repeat(22));
        assertTrue(settings.hasPendingBrowserAction());
        assertTrue("pair".equals(settings.browserOperation()));

        settings.saveDeviceToken("E".repeat(43));
        assertTrue(settings.isPaired());
        assertFalse(settings.hasPendingBrowserAction());
        assertTrue(settings.isBrowserPairing());

        settings.saveBrowserSubscription(
                "https://push.example/two", "F".repeat(87), "G".repeat(22));
        assertTrue(settings.hasPendingBrowserAction());
        assertTrue("renew".equals(settings.browserOperation()));
        settings.completeBrowserRenewal();
        assertFalse(settings.hasPendingBrowserAction());

        assertTrue(settings.beginBrowserRevoke());
        assertTrue(settings.hasPendingBrowserAction());
        assertTrue("revoke".equals(settings.browserOperation()));
    }

    private SharedPreferences inMemoryPreferences() {
        Map<String, Object> values = new HashMap<>();
        SharedPreferences.Editor editor =
                (SharedPreferences.Editor)
                        Proxy.newProxyInstance(
                                SharedPreferences.Editor.class.getClassLoader(),
                                new Class<?>[] {SharedPreferences.Editor.class},
                                (proxy, method, arguments) -> {
                                    if ("putBoolean".equals(method.getName())
                                            || "putString".equals(method.getName())) {
                                        values.put((String) arguments[0], arguments[1]);
                                        return proxy;
                                    }
                                    if ("remove".equals(method.getName())) {
                                        values.remove((String) arguments[0]);
                                        return proxy;
                                    }
                                    if ("apply".equals(method.getName())) return null;
                                    throw new AssertionError("Unexpected editor call: " + method.getName());
                                });
        return (SharedPreferences)
                Proxy.newProxyInstance(
                        SharedPreferences.class.getClassLoader(),
                        new Class<?>[] {SharedPreferences.class},
                        (proxy, method, arguments) -> {
                            if ("getBoolean".equals(method.getName())) {
                                return values.getOrDefault(
                                        (String) arguments[0],
                                        arguments[1]);
                            }
                            if ("getString".equals(method.getName())) {
                                return values.getOrDefault(
                                        (String) arguments[0],
                                        arguments[1]);
                            }
                            if ("edit".equals(method.getName())) return editor;
                            throw new AssertionError("Unexpected preferences call: " + method.getName());
                        });
    }
}
