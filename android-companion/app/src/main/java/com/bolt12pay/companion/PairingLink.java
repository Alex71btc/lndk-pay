package com.bolt12pay.companion;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

final class PairingLink {
    final String serverUrl;
    final String pairingToken;
    final String vapidPublicKey;

    private PairingLink(String serverUrl, String pairingToken, String vapidPublicKey) {
        this.serverUrl = serverUrl;
        this.pairingToken = pairingToken;
        this.vapidPublicKey = vapidPublicKey;
    }

    static PairingLink parse(String raw) {
        if (raw == null) return null;
        try {
            URI uri = new URI(raw);
            if (!"bolt12pay".equalsIgnoreCase(uri.getScheme())) return null;
            if (!"pair".equalsIgnoreCase(uri.getHost())) return null;
            Map<String, String> query = parseQuery(uri.getRawQuery());
            String serverUrl = ServerUrl.normalize(query.get("server"));
            String token = query.get("token");
            String vapid = query.get("vapid");
            if (serverUrl == null || !isToken(token) || !isVapidKey(vapid)) return null;
            return new PairingLink(serverUrl, token, vapid);
        } catch (URISyntaxException error) {
            return null;
        }
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> values = new HashMap<>();
        if (rawQuery == null) return values;
        for (String item : rawQuery.split("&")) {
            int separator = item.indexOf('=');
            if (separator <= 0) continue;
            String key = decode(item.substring(0, separator));
            String value = decode(item.substring(separator + 1));
            values.putIfAbsent(key, value);
        }
        return values;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static boolean isToken(String value) {
        return value != null
                && value.length() >= 32
                && value.length() <= 200
                && value.matches("[A-Za-z0-9_-]+");
    }

    private static boolean isVapidKey(String value) {
        if (value == null || value.length() != 87) return false;
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value + "=");
            return decoded.length == 65 && decoded[0] == 4;
        } catch (IllegalArgumentException error) {
            return false;
        }
    }
}
