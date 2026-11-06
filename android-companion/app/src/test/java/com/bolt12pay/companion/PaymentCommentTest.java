package com.bolt12pay.companion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class PaymentCommentTest {
    @Test
    public void sanitizesWhitespaceAndControlCharacters() {
        String comment = PaymentComment.sanitize("  first\r\nsecond\t\u0000\u202e 🚀  ");

        assertEquals("first second 🚀", comment);
        assertFalse(comment.contains("\u0000"));
        assertFalse(comment.contains("\u202e"));
    }

    @Test
    public void boundsByUnicodeCodePointsWithoutSplittingEmoji() {
        String comment = PaymentComment.sanitize("🚀".repeat(200));

        assertEquals(PaymentComment.MAX_LENGTH, comment.codePointCount(0, comment.length()));
        assertTrue(comment.endsWith("🚀"));
    }

    @Test
    public void missingCommentStaysMissingForOldPayloads() {
        assertEquals("", PaymentComment.sanitize(null));
        assertEquals("", PaymentComment.sanitize(" \n\t "));
    }
}
