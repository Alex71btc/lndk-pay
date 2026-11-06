package com.bolt12pay.companion;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONObject;
import org.unifiedpush.android.connector.data.PublicKeySet;
import org.unifiedpush.android.connector.data.PushEndpoint;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

final class PushApi {
    private PushApi() {}

    static void syncSubscription(Context context, PushEndpoint endpoint) {
        Context appContext = context.getApplicationContext();
        new Thread(() -> syncSubscriptionNow(appContext, endpoint), "companion-push-pair").start();
    }

    static void unregister(Context context, Runnable finished) {
        Context appContext = context.getApplicationContext();
        new Thread(
                        () -> {
                            PushSettings settings = new PushSettings(appContext);
                            String serverUrl = new ServerSettings(appContext).load();
                            String deviceToken = settings.deviceToken();
                            if (serverUrl != null && !deviceToken.isEmpty()) {
                                try {
                                    request(
                                            serverUrl + "/api/companion/subscription",
                                            "DELETE",
                                            deviceToken,
                                            null);
                                } catch (Exception ignored) {
                                    // UnifiedPush invalidates the endpoint even if the server is offline.
                                }
                            }
                            settings.clearRegistration();
                            if (finished != null) {
                                new Handler(Looper.getMainLooper()).post(finished);
                            }
                        },
                        "companion-push-unregister")
                .start();
    }

    private static void syncSubscriptionNow(Context context, PushEndpoint endpoint) {
        PushSettings settings = new PushSettings(context);
        try {
            String serverUrl = new ServerSettings(context).load();
            PublicKeySet keys = endpoint.getPubKeySet();
            if (serverUrl == null || keys == null) {
                throw new IOException(context.getString(R.string.push_encryption_unavailable));
            }
            JSONObject body = new JSONObject();
            body.put("endpoint", endpoint.getUrl());
            body.put("p256dh", keys.getPubKey());
            body.put("auth", keys.getAuth());

            String pairingToken = settings.pairingToken();
            String deviceToken = settings.deviceToken();
            if (!pairingToken.isEmpty()) {
                body.put("pairing_token", pairingToken);
                body.put("device_name", settings.deviceName());
                JSONObject response =
                        request(serverUrl + "/api/companion/pair", "POST", null, body);
                String issuedToken = response.getJSONObject("device").getString("device_token");
                settings.saveDeviceToken(issuedToken);
            } else if (!deviceToken.isEmpty()) {
                request(
                        serverUrl + "/api/companion/subscription",
                        "PUT",
                        deviceToken,
                        body);
                settings.setLastError("");
            }
        } catch (Exception error) {
            String message = error.getMessage();
            settings.setLastError(
                    message == null || message.isBlank()
                            ? context.getString(R.string.push_registration_failed)
                            : message);
        }
    }

    private static JSONObject request(
            String url,
            String method,
            String bearerToken,
            JSONObject body)
            throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(15_000);
        connection.setReadTimeout(15_000);
        connection.setInstanceFollowRedirects(false);
        connection.setUseCaches(false);
        connection.setRequestProperty("Accept", "application/json");
        if (bearerToken != null && !bearerToken.isEmpty()) {
            connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
        if (body != null) {
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            byte[] encoded = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.getOutputStream().write(encoded);
        }

        int status = connection.getResponseCode();
        InputStream stream =
                status >= 200 && status < 300
                        ? connection.getInputStream()
                        : connection.getErrorStream();
        String responseText = readFully(stream);
        connection.disconnect();
        JSONObject response;
        try {
            response = responseText.isBlank() ? new JSONObject() : new JSONObject(responseText);
        } catch (Exception error) {
            throw new IOException("Unreadable server response", error);
        }
        if (status < 200 || status >= 300) {
            throw new IOException(response.optString("detail", "Server rejected the request"));
        }
        return response;
    }

    private static String readFully(InputStream stream) throws IOException {
        if (stream == null) return "";
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) result.append(line);
            return result.toString();
        }
    }
}
