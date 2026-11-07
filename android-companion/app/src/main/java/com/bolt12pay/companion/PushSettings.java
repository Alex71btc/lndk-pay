package com.bolt12pay.companion;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class PushSettings {
    private static final String PREFS_NAME = "bolt12_pay_push";
    private static final String KEY_PAIRING_TOKEN = "pairing_token";
    private static final String KEY_BROWSER_PAIRING = "browser_pairing";
    private static final String KEY_PUSH_ENDPOINT = "push_endpoint";
    private static final String KEY_PUSH_P256DH = "push_p256dh";
    private static final String KEY_PUSH_AUTH = "push_auth";
    private static final String KEY_ACTIVE_PUSH_ENDPOINT = "active_push_endpoint";
    private static final String KEY_ACTIVE_PUSH_P256DH = "active_push_p256dh";
    private static final String KEY_ACTIVE_PUSH_AUTH = "active_push_auth";
    private static final String KEY_BROWSER_OPERATION = "browser_operation";
    private static final String KEY_BROWSER_ACTION_NONCE = "browser_action_nonce";
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

    void savePending(String pairingToken, String vapidPublicKey, String deviceName, boolean browserPairing) {
        preferences.edit()
                .putString(KEY_PAIRING_TOKEN, pairingToken)
                .putString(KEY_VAPID_PUBLIC_KEY, vapidPublicKey)
                .putString(KEY_DEVICE_NAME, deviceName)
                .putBoolean(KEY_BROWSER_PAIRING, browserPairing)
                .putString(
                        KEY_BROWSER_OPERATION,
                        browserPairing ? "pair" : "")
                .putString(
                        KEY_BROWSER_ACTION_NONCE,
                        browserPairing ? newActionNonce() : "")
                .remove(KEY_PUSH_ENDPOINT)
                .remove(KEY_PUSH_P256DH)
                .remove(KEY_PUSH_AUTH)
                .remove(KEY_ACTIVE_PUSH_ENDPOINT)
                .remove(KEY_ACTIVE_PUSH_P256DH)
                .remove(KEY_ACTIVE_PUSH_AUTH)
                .remove(KEY_DEVICE_TOKEN)
                .remove(KEY_LAST_ERROR)
                .apply();
    }

    boolean isBrowserPairing() {
        return preferences.getBoolean(KEY_BROWSER_PAIRING, false);
    }

    void saveBrowserSubscription(String endpoint, String p256dh, String auth) {
        if (isPaired()
                && endpoint.equals(activeBrowserEndpoint())
                && p256dh.equals(activeBrowserP256dh())
                && auth.equals(activeBrowserAuth())) {
            preferences.edit()
                    .remove(KEY_PUSH_ENDPOINT)
                    .remove(KEY_PUSH_P256DH)
                    .remove(KEY_PUSH_AUTH)
                    .remove(KEY_BROWSER_OPERATION)
                    .remove(KEY_BROWSER_ACTION_NONCE)
                    .remove(KEY_LAST_ERROR)
                    .apply();
            return;
        }

        String operation = isPairing() ? "pair" : "renew";
        boolean samePending =
                operation.equals(browserOperation())
                        && endpoint.equals(browserEndpoint())
                        && p256dh.equals(browserP256dh())
                        && auth.equals(browserAuth());
        SharedPreferences.Editor editor = preferences.edit()
                .putString(KEY_PUSH_ENDPOINT, endpoint)
                .putString(KEY_PUSH_P256DH, p256dh)
                .putString(KEY_PUSH_AUTH, auth)
                .putString(KEY_BROWSER_OPERATION, operation)
                .remove(KEY_LAST_ERROR)
                ;
        if (!samePending) {
            editor.putString(KEY_BROWSER_ACTION_NONCE, newActionNonce());
        }
        editor.apply();
    }

    String browserEndpoint() {
        return preferences.getString(KEY_PUSH_ENDPOINT, "");
    }

    String browserP256dh() {
        return preferences.getString(KEY_PUSH_P256DH, "");
    }

    String browserAuth() {
        return preferences.getString(KEY_PUSH_AUTH, "");
    }

    String browserOperation() {
        return preferences.getString(KEY_BROWSER_OPERATION, "");
    }

    String browserActionNonce() {
        return preferences.getString(KEY_BROWSER_ACTION_NONCE, "");
    }

    boolean hasPendingBrowserAction() {
        if (!isBrowserPairing() || browserActionNonce().isEmpty()) return false;
        String operation = browserOperation();
        if ("revoke".equals(operation)) return isPaired();
        if (!"pair".equals(operation) && !"renew".equals(operation)) return false;
        return !browserEndpoint().isEmpty()
                && !browserP256dh().isEmpty()
                && !browserAuth().isEmpty();
    }

    boolean beginBrowserRevoke() {
        if (!isBrowserPairing() || !isPaired()) return false;
        preferences.edit()
                .putString(KEY_BROWSER_OPERATION, "revoke")
                .putString(KEY_BROWSER_ACTION_NONCE, newActionNonce())
                .remove(KEY_LAST_ERROR)
                .apply();
        return true;
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
        SharedPreferences.Editor editor = preferences.edit()
                .putString(KEY_DEVICE_TOKEN, deviceToken)
                .remove(KEY_PAIRING_TOKEN)
                .remove(KEY_BROWSER_OPERATION)
                .remove(KEY_BROWSER_ACTION_NONCE)
                .remove(KEY_LAST_ERROR)
                ;
        if (isBrowserPairing()) {
            editor.putString(KEY_ACTIVE_PUSH_ENDPOINT, browserEndpoint())
                    .putString(KEY_ACTIVE_PUSH_P256DH, browserP256dh())
                    .putString(KEY_ACTIVE_PUSH_AUTH, browserAuth())
                    .remove(KEY_PUSH_ENDPOINT)
                    .remove(KEY_PUSH_P256DH)
                    .remove(KEY_PUSH_AUTH);
        }
        editor.apply();
    }

    void completeBrowserRenewal() {
        if (!"renew".equals(browserOperation()) || !hasPendingBrowserAction()) return;
        preferences.edit()
                .putString(KEY_ACTIVE_PUSH_ENDPOINT, browserEndpoint())
                .putString(KEY_ACTIVE_PUSH_P256DH, browserP256dh())
                .putString(KEY_ACTIVE_PUSH_AUTH, browserAuth())
                .remove(KEY_PUSH_ENDPOINT)
                .remove(KEY_PUSH_P256DH)
                .remove(KEY_PUSH_AUTH)
                .remove(KEY_BROWSER_OPERATION)
                .remove(KEY_BROWSER_ACTION_NONCE)
                .remove(KEY_LAST_ERROR)
                .apply();
    }

    void setLastError(String message) {
        preferences.edit().putString(KEY_LAST_ERROR, message == null ? "" : message).apply();
    }

    void clearRegistration() {
        preferences.edit()
                .remove(KEY_PAIRING_TOKEN)
                .remove(KEY_BROWSER_PAIRING)
                .remove(KEY_PUSH_ENDPOINT)
                .remove(KEY_PUSH_P256DH)
                .remove(KEY_PUSH_AUTH)
                .remove(KEY_ACTIVE_PUSH_ENDPOINT)
                .remove(KEY_ACTIVE_PUSH_P256DH)
                .remove(KEY_ACTIVE_PUSH_AUTH)
                .remove(KEY_BROWSER_OPERATION)
                .remove(KEY_BROWSER_ACTION_NONCE)
                .remove(KEY_VAPID_PUBLIC_KEY)
                .remove(KEY_DEVICE_TOKEN)
                .remove(KEY_DEVICE_NAME)
                .remove(KEY_LAST_ERROR)
                .remove(KEY_SEEN_EVENTS)
                .apply();
    }

    private String activeBrowserEndpoint() {
        return preferences.getString(KEY_ACTIVE_PUSH_ENDPOINT, "");
    }

    private String activeBrowserP256dh() {
        return preferences.getString(KEY_ACTIVE_PUSH_P256DH, "");
    }

    private String activeBrowserAuth() {
        return preferences.getString(KEY_ACTIVE_PUSH_AUTH, "");
    }

    private static String newActionNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
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
