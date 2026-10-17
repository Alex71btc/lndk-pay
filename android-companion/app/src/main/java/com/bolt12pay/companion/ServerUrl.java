package com.bolt12pay.companion;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

final class ServerUrl {
    private ServerUrl() {}

    static String normalize(String raw) {
        if (raw == null) return null;

        try {
            URI parsed = new URI(raw.trim());
            if (!"https".equalsIgnoreCase(parsed.getScheme())) return null;
            if (parsed.getHost() == null || parsed.getUserInfo() != null) return null;
            if (parsed.getQuery() != null || parsed.getFragment() != null) return null;
            if (!parsed.getPath().isEmpty() && !"/".equals(parsed.getPath())) return null;

            return new URI(
                            "https",
                            null,
                            parsed.getHost(),
                            parsed.getPort(),
                            null,
                            null,
                            null)
                    .toString();
        } catch (URISyntaxException error) {
            return null;
        }
    }

    static String paymentHandoff(String baseUrl, String lightningTarget) {
        String normalizedBase = normalize(baseUrl);
        String normalizedTarget = LightningTarget.normalize(lightningTarget);
        if (normalizedBase == null || normalizedTarget == null) return null;
        return normalizedBase + "/pay-intent#lightning=" + encodeFragmentValue(normalizedTarget);
    }

    private static String encodeFragmentValue(String value) {
        StringBuilder encoded = new StringBuilder();
        for (byte current : value.getBytes(StandardCharsets.UTF_8)) {
            int character = current & 0xff;
            boolean unreserved =
                    (character >= 'a' && character <= 'z')
                            || (character >= 'A' && character <= 'Z')
                            || (character >= '0' && character <= '9')
                            || character == '-'
                            || character == '.'
                            || character == '_'
                            || character == '~';
            if (unreserved) {
                encoded.append((char) character);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit(character >>> 4, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(character & 0x0f, 16)));
            }
        }
        return encoded.toString();
    }
}
