package com.xebyte.core;

import junit.framework.TestCase;

/**
 * Unit tests for the /search_byte_patterns hex-pattern parser.
 *
 * <p>The parser it replaced accepted malformed input and searched for something the caller
 * never wrote. Two cases mattered most, and both are pinned here: an odd digit count read the
 * trailing nibble as a whole byte ("9E E5 D" searched 9E E5 0D and reported no matches against
 * memory holding 9E E5 DD), and a nibble wildcard silently widened to a whole-byte wildcard
 * ("FF D?" matched the same set as "FF ??"). The first is a false negative, the second a false
 * positive, and the tool exists to answer exactly this kind of question.
 *
 * <p>No loaded program is required: parsing is separated from the memory scan precisely so
 * these rules are testable offline.
 */
public class AnalysisServiceBytePatternParseTest extends TestCase {

    private static AnalysisService.ParsedPattern parse(String pattern) {
        return AnalysisService.parseBytePattern(pattern);
    }

    private static void assertRejected(String pattern, String expectedSubstring) {
        AnalysisService.ParsedPattern p = parse(pattern);
        assertTrue("expected " + pattern + " to be rejected", p.failed());
        assertTrue("message was: " + p.error(), p.error().contains(expectedSubstring));
    }

    public void testExactBytesGetFullMasks() {
        AnalysisService.ParsedPattern p = parse("55 8B EC");
        assertFalse(p.error(), p.failed());
        assertEquals(3, p.value().length);
        assertEquals(0x55, p.value()[0]);
        assertEquals(0x8B, p.value()[1]);
        assertEquals(0xEC, p.value()[2]);
        for (int m : p.mask()) {
            assertEquals(0xFF, m);
        }
    }

    public void testWhitespaceIsOptionalAndFreeForm() {
        // "5 5 8B" already worked before this change; keep it working.
        AnalysisService.ParsedPattern spaced = parse("5 5 8B");
        AnalysisService.ParsedPattern tight = parse("558B");
        assertFalse(spaced.failed());
        assertFalse(tight.failed());
        assertEquals(tight.value()[0], spaced.value()[0]);
        assertEquals(tight.value()[1], spaced.value()[1]);
    }

    public void testLowercaseIsAccepted() {
        AnalysisService.ParsedPattern p = parse("e8 ff");
        assertFalse(p.error(), p.failed());
        assertEquals(0xE8, p.value()[0]);
        assertEquals(0xFF, p.value()[1]);
    }

    public void testWholeByteWildcard() {
        AnalysisService.ParsedPattern p = parse("E8 ?? ?? ?? ??");
        assertFalse(p.error(), p.failed());
        assertEquals(5, p.value().length);
        assertEquals(0xFF, p.mask()[0]);
        for (int i = 1; i < 5; i++) {
            assertEquals("byte " + i + " should be a full wildcard", 0x00, p.mask()[i]);
            assertEquals(0x00, p.value()[i]);
        }
    }

    /** The regression that matters most on the false-positive side. */
    public void testHighNibbleFixedLowNibbleWildcard() {
        AnalysisService.ParsedPattern p = parse("FF D?");
        assertFalse(p.error(), p.failed());
        assertEquals(0xFF, p.mask()[0]);
        assertEquals("D? must fix the high nibble only, not widen to a whole-byte wildcard",
                0xF0, p.mask()[1]);
        assertEquals(0xD0, p.value()[1]);
    }

    public void testLowNibbleFixedHighNibbleWildcard() {
        AnalysisService.ParsedPattern p = parse("?5 8B");
        assertFalse(p.error(), p.failed());
        assertEquals(0x0F, p.mask()[0]);
        assertEquals(0x05, p.value()[0]);
        assertEquals(0xFF, p.mask()[1]);
    }

    public void testDotIsASynonymForQuestionMark() {
        AnalysisService.ParsedPattern dots = parse("FF D.");
        AnalysisService.ParsedPattern qs = parse("FF D?");
        assertFalse(dots.failed());
        assertEquals(qs.mask()[1], dots.mask()[1]);
        assertEquals(qs.value()[1], dots.value()[1]);
    }

    /** The regression that matters most on the false-negative side. */
    public void testOddDigitCountIsRejectedNotSilentlyPadded() {
        assertRejected("9E E5 D", "each byte needs 2");
        assertRejected("E8C", "each byte needs 2");
        // Odd length combined with a wildcard used to throw ArrayIndexOutOfBounds instead.
        assertRejected("E8?", "each byte needs 2");
        assertRejected("?", "each byte needs 2");
    }

    public void testNonHexCharactersAreRejectedWithPosition() {
        assertRejected("ZZ", "'Z' at index 0");
        // '+' and '-' used to be swallowed by Integer.parseInt as sign characters, so
        // "15+AFA9E" matched real memory holding 15 0A FA 9E.
        assertRejected("15+AFA9E", "'+' at index 2");
        assertRejected("-1", "'-' at index 0");
        assertRejected("0xE8", "'X' at index 1");
    }

    public void testAllWildcardPatternIsRejected() {
        assertRejected("??", "matches at every address");
        assertRejected("?? ?? ??", "matches at every address");
    }

    public void testEmptyAndBlankRejected() {
        assertRejected(null, "pattern is required");
        assertRejected("", "pattern is required");
        assertRejected("   ", "pattern is required");
    }

    public void testOverlongPatternRejected() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i <= AnalysisService.MAX_PATTERN_BYTES; i++) {
            sb.append("AA");
        }
        assertRejected(sb.toString(), "the maximum is " + AnalysisService.MAX_PATTERN_BYTES);
    }

    public void testMaximumLengthPatternIsAccepted() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < AnalysisService.MAX_PATTERN_BYTES; i++) {
            sb.append("AA");
        }
        AnalysisService.ParsedPattern p = parse(sb.toString());
        assertFalse(p.error(), p.failed());
        assertEquals(AnalysisService.MAX_PATTERN_BYTES, p.value().length);
    }

    /**
     * The value/mask pair must satisfy ((data ^ value) & mask) == 0 for a matching byte and
     * != 0 otherwise - the same expression the scan loop uses. Checked directly so the parser
     * and the matcher cannot drift apart.
     */
    public void testMaskSemanticsMatchTheMatcherExpression() {
        AnalysisService.ParsedPattern p = parse("FF D?");
        int[] v = p.value();
        int[] m = p.mask();

        assertEquals("FF matches FF", 0, ((0xFF ^ v[0]) & m[0]));
        assertTrue("FF must not match FE", ((0xFE ^ v[0]) & m[0]) != 0);

        assertEquals("D? matches D0", 0, ((0xD0 ^ v[1]) & m[1]));
        assertEquals("D? matches DD", 0, ((0xDD ^ v[1]) & m[1]));
        assertEquals("D? matches DF", 0, ((0xDF ^ v[1]) & m[1]));
        assertTrue("D? must not match C3", ((0xC3 ^ v[1]) & m[1]) != 0);
        assertTrue("D? must not match ED", ((0xED ^ v[1]) & m[1]) != 0);
    }

    public void testFullWildcardByteMatchesAnything() {
        AnalysisService.ParsedPattern p = parse("E8 ??");
        int[] v = p.value();
        int[] m = p.mask();
        for (int b = 0; b <= 0xFF; b++) {
            assertEquals("?? must match " + b, 0, ((b ^ v[1]) & m[1]));
        }
    }
}
