package com.bolt12pay.companion;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

final class LightningTarget {
    static final int MAX_LENGTH = 8192;

    private static final Pattern ALPHANUMERIC = Pattern.compile("^[a-zA-Z0-9]+$");
    private static final Pattern BOLT11_PREFIX =
            Pattern.compile("^(lnbc|lntb|lnbcrt)\\d*[munp]?1.*$");

    private LightningTarget() {}

    static String normalize(String raw) {
        if (raw == null) return null;

        String value = unwrapPaymentUri(raw.trim());
        if (value == null) return null;
        if (value.isEmpty() || value.length() > MAX_LENGTH) return null;
        if (!ALPHANUMERIC.matcher(value).matches()) return null;

        String lower = value.toLowerCase(Locale.ROOT);
        String upper = value.toUpperCase(Locale.ROOT);
        if (!value.equals(lower) && !value.equals(upper)) return null;

        if (lower.startsWith("lno1") || BOLT11_PREFIX.matcher(lower).matches()) {
            return value;
        }
        return null;
    }

    private static String unwrapPaymentUri(String raw) {
        if (raw.regionMatches(true, 0, "lightning:", 0, "lightning:".length())) {
            return raw.replaceFirst("(?i)^lightning:(//)?", "");
        }

        if (raw.regionMatches(true, 0, "bitcoin:?", 0, "bitcoin:?".length())) {
            return extractBip321Target(raw.substring("bitcoin:?".length()));
        }

        if (raw.regionMatches(true, 0, "bitcoin:", 0, "bitcoin:".length())) {
            return null;
        }

        return raw;
    }

    private static String extractBip321Target(String rawQuery) {
        String selected = null;
        for (String part : rawQuery.split("&", -1)) {
            int separator = part.indexOf('=');
            if (separator <= 0) continue;

            String name = percentDecode(part.substring(0, separator));
            String value = percentDecode(part.substring(separator + 1));
            if (name == null || value == null) return null;

            boolean isOffer = "lno".equalsIgnoreCase(name);
            boolean isInvoice = "lightning".equalsIgnoreCase(name);
            if (!isOffer && !isInvoice) continue;
            if (selected != null || value.isEmpty()) return null;
            selected = value;
        }
        return selected;
    }

    private static String percentDecode(String encoded) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(encoded.length());
        for (int index = 0; index < encoded.length(); ) {
            char character = encoded.charAt(index);
            if (character == '%') {
                if (index + 2 >= encoded.length()) return null;
                int high = Character.digit(encoded.charAt(index + 1), 16);
                int low = Character.digit(encoded.charAt(index + 2), 16);
                if (high < 0 || low < 0) return null;
                bytes.write((high << 4) + low);
                index += 3;
                continue;
            }

            if (character > 0x7f) return null;
            bytes.write((byte) character);
            index += 1;
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }
}
