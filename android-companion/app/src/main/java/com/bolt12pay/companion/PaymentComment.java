package com.bolt12pay.companion;

import java.text.Normalizer;

final class PaymentComment {
    static final int MAX_LENGTH = 160;

    private PaymentComment() {}

    static String sanitize(String value) {
        if (value == null || value.isEmpty()) return "";

        String normalized = Normalizer.normalize(value, Normalizer.Form.NFC);
        StringBuilder cleaned = new StringBuilder();
        boolean pendingSpace = false;
        for (int offset = 0; offset < normalized.length(); ) {
            int codePoint = normalized.codePointAt(offset);
            offset += Character.charCount(codePoint);

            if (Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint)) {
                pendingSpace = cleaned.length() > 0;
                continue;
            }

            int type = Character.getType(codePoint);
            boolean unsafeControl =
                    type == Character.CONTROL
                            || type == Character.FORMAT
                            || type == Character.SURROGATE
                            || type == Character.PRIVATE_USE
                            || type == Character.UNASSIGNED;
            if (unsafeControl && codePoint != 0x200d) continue;

            if (pendingSpace) {
                cleaned.append(' ');
                pendingSpace = false;
            }
            cleaned.appendCodePoint(codePoint);
        }

        String comment = cleaned.toString().trim();
        int codePoints = comment.codePointCount(0, comment.length());
        if (codePoints > MAX_LENGTH) {
            int end = comment.offsetByCodePoints(0, MAX_LENGTH);
            comment = comment.substring(0, end).trim();
        }
        while (comment.endsWith("\u200d")) {
            comment = comment.substring(0, comment.length() - 1).trim();
        }
        return comment;
    }
}
