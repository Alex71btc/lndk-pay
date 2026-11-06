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

    private SharedPreferences inMemoryPreferences() {
        Map<String, Boolean> booleans = new HashMap<>();
        SharedPreferences.Editor editor =
                (SharedPreferences.Editor)
                        Proxy.newProxyInstance(
                                SharedPreferences.Editor.class.getClassLoader(),
                                new Class<?>[] {SharedPreferences.Editor.class},
                                (proxy, method, arguments) -> {
                                    if ("putBoolean".equals(method.getName())) {
                                        booleans.put((String) arguments[0], (Boolean) arguments[1]);
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
                                return booleans.getOrDefault(
                                        (String) arguments[0],
                                        (Boolean) arguments[1]);
                            }
                            if ("edit".equals(method.getName())) return editor;
                            throw new AssertionError("Unexpected preferences call: " + method.getName());
                        });
    }
}
