using System.Runtime.CompilerServices;
using System.Text.Json;
using LinkKeys.LocalRp.Crypto;

namespace LinkKeys.LocalRp.Tests.TestUtil;

/// <summary>
/// Loads <c>sdks/local-rp/conformance/*.json</c> fixture files for tests, using the BCL's
/// <see cref="System.Text.Json"/> (part of the shared framework on net8.0 — no extra
/// package reference needed, unlike the Java SDK's hand-rolled MiniJson, which had to
/// avoid a JSON library entirely since JCA has none built in).
/// </summary>
public static class Fixtures
{
    /// <summary>
    /// The <c>sdks/local-rp/conformance/</c> directory, located relative to this source
    /// file's own compile-time path (baked in via <see cref="CallerFilePathAttribute"/>)
    /// rather than a working-directory assumption, so <c>dotnet test</c> finds it
    /// regardless of the invocation directory.
    /// </summary>
    private static string ConformanceDir([CallerFilePath] string thisFile = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "..", "..", "conformance"));

    public static JsonElement Load(string name)
    {
        var path = Path.Combine(ConformanceDir(), name);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"conformance fixture not found: {path} (run the generator?)", path);
        }

        using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
        return doc.RootElement.Clone();
    }

    public static byte[] Hex(string s) => LinkKeys.LocalRp.Crypto.Hex.Decode(s);

    // -----------------------------------------------------------------
    // JsonElement navigation helpers
    // -----------------------------------------------------------------

    public static JsonElement Get(this JsonElement e, string key)
    {
        if (e.TryGetProperty(key, out var v))
        {
            return v;
        }

        throw new InvalidOperationException($"missing key '{key}' in {e}");
    }

    public static JsonElement? GetOrNull(this JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) ? v : null;

    public static string? GetStringOrNull(this JsonElement e, string key)
    {
        var v = e.GetOrNull(key);
        return v is null || v.Value.ValueKind == JsonValueKind.Null ? null : v.Value.GetString();
    }

    public static IEnumerable<JsonElement> AsArray(this JsonElement e) => e.EnumerateArray();

    public static string AsString(this JsonElement e) => e.GetString()!;

    public static bool AsBoolean(this JsonElement e) => e.GetBoolean();

    public static long AsLong(this JsonElement e) => e.GetInt64();

    public static bool IsNull(this JsonElement e) => e.ValueKind == JsonValueKind.Null;
}
