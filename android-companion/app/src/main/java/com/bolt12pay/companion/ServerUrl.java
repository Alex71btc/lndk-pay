package com.bolt12pay.companion;

import java.net.URI;
import java.net.URISyntaxException;

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
        return normalizedBase + "/pay-intent#lightning=" + normalizedTarget;
    }
}
