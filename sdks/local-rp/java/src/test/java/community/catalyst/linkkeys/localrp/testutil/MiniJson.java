package community.catalyst.linkkeys.localrp.testutil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, dependency-free JSON parser for reading the conformance vector
 * fixtures in tests. This SDK has zero runtime dependencies (design doc:
 * "Zero external dependencies (test framework excepted)"), and a JSON
 * library counts as a dependency even at test scope, so the conformance
 * vector loader hand-parses JSON the same way this SDK hand-parses CBOR.
 *
 * <p>Only what {@code sdks/local-rp/conformance/*.json} needs: objects,
 * arrays, strings (with standard escapes), numbers, booleans, and null.
 * Numbers are returned as {@link Double} or {@link Long} depending on
 * whether they contain a {@code .}/exponent; the fixtures only ever need
 * integers, so callers use {@link JsonValue#asLong()}.
 */
public final class MiniJson {
    private MiniJson() {}

    public static JsonValue parse(String text) {
        Parser p = new Parser(text);
        p.skipWhitespace();
        JsonValue v = p.parseValue();
        p.skipWhitespace();
        if (!p.atEnd()) {
            throw new IllegalArgumentException("trailing content after JSON value at position " + p.pos);
        }
        return v;
    }

    /** A parsed JSON value: object ({@code Map<String,JsonValue>}), array, string, number, boolean, or null. */
    public static final class JsonValue {
        private final Object raw;

        private JsonValue(Object raw) {
            this.raw = raw;
        }

        public boolean isNull() {
            return raw == null;
        }

        public String asString() {
            if (raw instanceof String s) {
                return s;
            }
            throw new IllegalStateException("not a string: " + raw);
        }

        public boolean asBoolean() {
            if (raw instanceof Boolean b) {
                return b;
            }
            throw new IllegalStateException("not a boolean: " + raw);
        }

        public long asLong() {
            if (raw instanceof Long l) {
                return l;
            }
            if (raw instanceof Double d) {
                return d.longValue();
            }
            throw new IllegalStateException("not a number: " + raw);
        }

        @SuppressWarnings("unchecked")
        public List<JsonValue> asArray() {
            if (raw instanceof List<?> list) {
                return (List<JsonValue>) list;
            }
            throw new IllegalStateException("not an array: " + raw);
        }

        @SuppressWarnings("unchecked")
        public Map<String, JsonValue> asObject() {
            if (raw instanceof Map<?, ?> map) {
                return (Map<String, JsonValue>) map;
            }
            throw new IllegalStateException("not an object: " + raw);
        }

        public JsonValue get(String key) {
            JsonValue v = asObject().get(key);
            if (v == null) {
                throw new IllegalStateException("missing key '" + key + "' in " + raw);
            }
            return v;
        }

        public JsonValue getOrNull(String key) {
            return asObject().get(key);
        }

        /** {@code get(key).asString()}, or {@code null} if the key is absent or its value is JSON null. */
        public String getStringOrNull(String key) {
            JsonValue v = getOrNull(key);
            return (v == null || v.isNull()) ? null : v.asString();
        }
    }

    private static final class Parser {
        private final String s;
        private int pos = 0;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        void skipWhitespace() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        private char peek() {
            if (pos >= s.length()) {
                throw new IllegalArgumentException("unexpected end of JSON input");
            }
            return s.charAt(pos);
        }

        private void expect(char c) {
            if (peek() != c) {
                throw new IllegalArgumentException("expected '" + c + "' at position " + pos + ", got '" + peek() + "'");
            }
            pos++;
        }

        JsonValue parseValue() {
            skipWhitespace();
            char c = peek();
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> new JsonValue(parseString());
                case 't' -> {
                    expectLiteral("true");
                    yield new JsonValue(Boolean.TRUE);
                }
                case 'f' -> {
                    expectLiteral("false");
                    yield new JsonValue(Boolean.FALSE);
                }
                case 'n' -> {
                    expectLiteral("null");
                    yield new JsonValue(null);
                }
                default -> parseNumber();
            };
        }

        private void expectLiteral(String literal) {
            if (!s.regionMatches(pos, literal, 0, literal.length())) {
                throw new IllegalArgumentException("expected '" + literal + "' at position " + pos);
            }
            pos += literal.length();
        }

        private JsonValue parseObject() {
            expect('{');
            Map<String, JsonValue> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return new JsonValue(map);
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                JsonValue value = parseValue();
                map.put(key, value);
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                    continue;
                }
                if (c == '}') {
                    pos++;
                    break;
                }
                throw new IllegalArgumentException("expected ',' or '}' at position " + pos);
            }
            return new JsonValue(map);
        }

        private JsonValue parseArray() {
            expect('[');
            List<JsonValue> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return new JsonValue(list);
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    pos++;
                    continue;
                }
                if (c == ']') {
                    pos++;
                    break;
                }
                throw new IllegalArgumentException("expected ',' or ']' at position " + pos);
            }
            return new JsonValue(list);
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(pos++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            String hex = s.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        default -> throw new IllegalArgumentException("invalid escape '\\" + esc + "'");
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private JsonValue parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            boolean isDouble = false;
            while (pos < s.length() && (Character.isDigit(s.charAt(pos)) || "+-.eE".indexOf(s.charAt(pos)) >= 0)) {
                char c = s.charAt(pos);
                if (c == '.' || c == 'e' || c == 'E') {
                    isDouble = true;
                }
                pos++;
            }
            String text = s.substring(start, pos);
            if (isDouble) {
                return new JsonValue(Double.parseDouble(text));
            }
            return new JsonValue(Long.parseLong(text));
        }
    }
}
