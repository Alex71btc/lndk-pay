package com.bolt12pay.companion;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class PushSettings {
    private static final String PREFS_NAME = "bolt12_pay_push";
    private static final String KEY_PAIRING_TOKEN = "pairing_token";
    private static final String KEY_VAPID_PUBLIC_KEY = "vapid_public_key";
    private static final String KEY_DEVICE_TOKEN = "device_token";
    private static final String KEY_DEVICE_NAME = "device_name";
    private static final String KEY_LAST_ERROR = "last_error";
    private static final String KEY_SEEN_EVENTS = "seen_events";
    private static final String KEY_SHOW_PAYMENT_COMMENTS = "show_payment_comments";
    private static final int MAX_SEEN_EVENTS = 100;

    private final SharedPreferences preferences;

    PushSettings(Context context) {
        this(context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE));
    }

    PushSettings(SharedPreferences preferences) {
        this.preferences = preferences;
    }

    void savePending(String pairingToken, String vapidPublicKey, String deviceName) {
        preferences.edit()
                .putString(KEY_PAIRING_TOKEN, pairingToken)
                .putString(KEY_VAPID_PUBLIC_KEY, vapidPublicKey)
                .putString(KEY_DEVICE_NAME, deviceName)
                .remove(KEY_LAST_ERROR)
                .apply();
    }

    String pairingToken() {
        return preferences.getString(KEY_PAIRING_TOKEN, "");
    }

    String vapidPublicKey() {
        return preferences.getString(KEY_VAPID_PUBLIC_KEY, "");
    }

    String deviceToken() {
        return preferences.getString(KEY_DEVICE_TOKEN, "");
    }

    String deviceName() {
        return preferences.getString(KEY_DEVICE_NAME, "Android Companion");
    }

    String lastError() {
        return preferences.getString(KEY_LAST_ERROR, "");
    }

    boolean isPaired() {
        return !deviceToken().isEmpty();
    }

    boolean isPairing() {
        return !pairingToken().isEmpty();
    }

    boolean showPaymentComments() {
        return preferences.getBoolean(KEY_SHOW_PAYMENT_COMMENTS, false);
    }

    void setShowPaymentComments(boolean showPaymentComments) {
        preferences.edit()
                .putBoolean(KEY_SHOW_PAYMENT_COMMENTS, showPaymentComments)
                .apply();
    }

    void saveDeviceToken(String deviceToken) {
        preferences.edit()
                .putString(KEY_DEVICE_TOKEN, deviceToken)
                .remove(KEY_PAIRING_TOKEN)
                .remove(KEY_LAST_ERROR)
                .apply();
    }

    void setLastError(String message) {
        preferences.edit().putString(KEY_LAST_ERROR, message == null ? "" : message).apply();
    }

    void clearRegistration() {
        preferences.edit()
                .remove(KEY_PAIRING_TOKEN)
                .remove(KEY_VAPID_PUBLIC_KEY)
                .remove(KEY_DEVICE_TOKEN)
                .remove(KEY_DEVICE_NAME)
                .remove(KEY_LAST_ERROR)
                .remove(KEY_SEEN_EVENTS)
                .apply();
    }

    synchronized boolean rememberEvent(String eventId) {
        if (eventId == null || eventId.isEmpty()) return false;
        Set<String> stored = preferences.getStringSet(KEY_SEEN_EVENTS, Collections.emptySet());
        LinkedHashSet<String> events = new LinkedHashSet<>(stored);
        if (!events.add(eventId)) return false;
        if (events.size() > MAX_SEEN_EVENTS) {
            List<String> ordered = new ArrayList<>(events);
            events.clear();
            events.addAll(ordered.subList(ordered.size() - MAX_SEEN_EVENTS, ordered.size()));
        }
        preferences.edit().putStringSet(KEY_SEEN_EVENTS, events).apply();
        return true;
    }
}
