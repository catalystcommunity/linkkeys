package community.catalyst.linkkeys.localrp.kt.testutil

/**
 * A minimal, dependency-free JSON parser for reading the conformance vector
 * fixtures in tests -- ported from the Java sibling SDK's
 * `testutil.MiniJson` (test-scope only; this SDK's runtime dependency is
 * just the sibling Java SDK project, see README's "Architecture decision").
 *
 * Only what the JSON vector files under `sdks/local-rp/conformance` need:
 * objects, arrays, strings (with standard escapes), numbers, booleans, and
 * null.
 */
object MiniJson {
    fun parse(text: String): JsonValue {
        val p = Parser(text)
        p.skipWhitespace()
        val v = p.parseValue()
        p.skipWhitespace()
        require(p.atEnd()) { "trailing content after JSON value at position ${p.pos}" }
        return v
    }

    /** A parsed JSON value: object, array, string, number, boolean, or null. */
    class JsonValue internal constructor(private val raw: Any?) {
        fun isNull(): Boolean = raw == null

        fun asString(): String = raw as? String ?: error("not a string: $raw")

        fun asBoolean(): Boolean = raw as? Boolean ?: error("not a boolean: $raw")

        fun asLong(): Long = when (raw) {
            is Long -> raw
            is Double -> raw.toLong()
            else -> error("not a number: $raw")
        }

        @Suppress("UNCHECKED_CAST")
        fun asArray(): List<JsonValue> = raw as? List<JsonValue> ?: error("not an array: $raw")

        @Suppress("UNCHECKED_CAST")
        fun asObject(): Map<String, JsonValue> = raw as? Map<String, JsonValue> ?: error("not an object: $raw")

        fun get(key: String): JsonValue = asObject()[key] ?: error("missing key '$key' in $raw")

        fun getOrNull(key: String): JsonValue? = asObject()[key]

        /** `get(key).asString()`, or `null` if the key is absent or its value is JSON null. */
        fun getStringOrNull(key: String): String? = getOrNull(key)?.let { if (it.isNull()) null else it.asString() }
    }

    private class Parser(val s: String) {
        var pos = 0

        fun atEnd(): Boolean = pos >= s.length

        fun skipWhitespace() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        private fun peek(): Char {
            require(pos < s.length) { "unexpected end of JSON input" }
            return s[pos]
        }

        private fun expect(c: Char) {
            require(peek() == c) { "expected '$c' at position $pos, got '${peek()}'" }
            pos++
        }

        fun parseValue(): JsonValue {
            skipWhitespace()
            return when (peek()) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonValue(parseString())
                't' -> {
                    expectLiteral("true")
                    JsonValue(true)
                }
                'f' -> {
                    expectLiteral("false")
                    JsonValue(false)
                }
                'n' -> {
                    expectLiteral("null")
                    JsonValue(null)
                }
                else -> parseNumber()
            }
        }

        private fun expectLiteral(literal: String) {
            require(s.regionMatches(pos, literal, 0, literal.length)) { "expected '$literal' at position $pos" }
            pos += literal.length
        }

        private fun parseObject(): JsonValue {
            expect('{')
            val map = LinkedHashMap<String, JsonValue>()
            skipWhitespace()
            if (peek() == '}') {
                pos++
                return JsonValue(map)
            }
            while (true) {
                skipWhitespace()
                val key = parseString()
                skipWhitespace()
                expect(':')
                val value = parseValue()
                map[key] = value
                skipWhitespace()
                when (peek()) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        break
                    }
                    else -> error("expected ',' or '}' at position $pos")
                }
            }
            return JsonValue(map)
        }

        private fun parseArray(): JsonValue {
            expect('[')
            val list = ArrayList<JsonValue>()
            skipWhitespace()
            if (peek() == ']') {
                pos++
                return JsonValue(list)
            }
            while (true) {
                list.add(parseValue())
                skipWhitespace()
                when (peek()) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        break
                    }
                    else -> error("expected ',' or ']' at position $pos")
                }
            }
            return JsonValue(list)
        }

        private fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                val c = s[pos++]
                if (c == '"') break
                if (c == '\\') {
                    when (val esc = s[pos++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(pos, pos + 4)
                            pos += 4
                            sb.append(hex.toInt(16).toChar())
                        }
                        else -> error("invalid escape '\\$esc'")
                    }
                } else {
                    sb.append(c)
                }
            }
            return sb.toString()
        }

        private fun parseNumber(): JsonValue {
            val start = pos
            if (peek() == '-') pos++
            var isDouble = false
            while (pos < s.length && (s[pos].isDigit() || "+-.eE".indexOf(s[pos]) >= 0)) {
                if (s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E') isDouble = true
                pos++
            }
            val text = s.substring(start, pos)
            return if (isDouble) JsonValue(text.toDouble()) else JsonValue(text.toLong())
        }
    }
}
