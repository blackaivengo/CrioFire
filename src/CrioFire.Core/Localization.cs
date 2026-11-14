using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace CrioFire.Core;

/// <summary>A language the app is translated into.</summary>
/// <param name="Code">The file name and culture: de, pt-BR, zh-Hans.</param>
/// <param name="Name">The language's own name for itself: Deutsch, 日本語.</param>
/// <param name="EnglishName">German, Japanese.</param>
/// <param name="RightToLeft">Written right to left (Arabic, Urdu): windows are mirrored.</param>
public sealed record Language(string Code, string Name, string EnglishName, bool RightToLeft = false);

/// <summary>
/// The desktop app's languages, and how the one to use is chosen. English is the original: every
/// text is written in English in the code and in the XAML, and is itself the key of its
/// translation (<see cref="L"/>).
/// </summary>
public static class Languages
{
    public const string English = "en";

    /// <summary>"Same as Windows": the preference value that follows the Windows display language.</summary>
    public const string System = "system";

    /// <summary>The 16 most widely spoken languages that Windows can display, English first.</summary>
    public static IReadOnlyList<Language> All { get; } =
    [
        new("en", "English", "English"),
        new("zh-Hans", "中文（简体）", "Chinese (Simplified)"),
        new("hi", "हिन्दी", "Hindi"),
        new("es", "Español", "Spanish"),
        new("ar", "العربية", "Arabic", RightToLeft: true),
        new("fr", "Français", "French"),
        new("bn", "বাংলা", "Bengali"),
        new("pt-BR", "Português (Brasil)", "Portuguese (Brazil)"),
        new("ru", "Русский", "Russian"),
        new("id", "Bahasa Indonesia", "Indonesian"),
        new("ur", "اردو", "Urdu", RightToLeft: true),
        new("de", "Deutsch", "German"),
        new("ja", "日本語", "Japanese"),
        new("tr", "Türkçe", "Turkish"),
        new("ko", "한국어", "Korean"),
        new("vi", "Tiếng Việt", "Vietnamese"),
    ];

    public static Language? Find(string? code) =>
        All.FirstOrDefault(l => string.Equals(l.Code, code, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The language for a preference ("system" or a code) and the Windows display language: the
    /// preference when it names one of ours, else the closest match to Windows (zh-CN and zh-SG →
    /// zh-Hans, pt-PT → pt-BR, de-AT → de), else English.
    /// </summary>
    public static Language Resolve(string? preference, CultureInfo windows)
    {
        ArgumentNullException.ThrowIfNull(windows);
        if (Find(preference) is { } chosen)
        {
            return chosen;
        }

        for (var culture = windows; !string.IsNullOrEmpty(culture.Name); culture = culture.Parent)
        {
            if (Find(culture.Name) is { } exact)
            {
                return exact;
            }

            if (culture.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase))
            {
                // Traditional Chinese (zh-TW, zh-HK, zh-Hant) is not translated: English rather than the wrong script.
                return culture.Name.Contains("Hant", StringComparison.OrdinalIgnoreCase) || culture.Name is "zh-TW" or "zh-HK" or "zh-MO"
                    ? All[0]
                    : Find("zh-Hans")!;
            }
        }

        var language = windows.TwoLetterISOLanguageName;
        return All.FirstOrDefault(l => l.Code.Split('-')[0].Equals(language, StringComparison.OrdinalIgnoreCase)) ?? All[0];
    }
}

/// <summary>A language's translations: English text → translated text. Missing entries stay English.</summary>
public sealed class Catalog
{
    private readonly Dictionary<string, string> _texts;

    public Catalog(IDictionary<string, string> texts) => _texts = new Dictionary<string, string>(texts, StringComparer.Ordinal);

    public static Catalog Empty { get; } = new(new Dictionary<string, string>());

    public int Count => _texts.Count;

    public IReadOnlyDictionary<string, string> Texts => _texts;

    /// <summary>
    /// A translation file: one JSON object, English text → translation. Keys starting with "//" are
    /// notes for translators; empty translations are skipped (still to do).
    /// </summary>
    public static Catalog Parse(string json)
    {
        var texts = new Dictionary<string, string>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("A translation file holds one JSON object.");
        }

        foreach (var entry in doc.RootElement.EnumerateObject())
        {
            if (!entry.Name.StartsWith("//", StringComparison.Ordinal) && entry.Value.ValueKind == JsonValueKind.String
                && entry.Value.GetString() is { Length: > 0 } text)
            {
                texts[entry.Name] = text;
            }
        }

        return new Catalog(texts);
    }

    public string? Find(string english) => _texts.GetValueOrDefault(english);
}

/// <summary>
/// Translates the desktop app's texts. Write the English text where it is used and wrap it:
/// <c>L.T("Clear history")</c>, or with values, <c>L.T($"Allowed {name} for {minutes} minutes.")</c>,
/// which is looked up as "Allowed {0} for {1} minutes." and filled in after translation, so
/// translators can move the values. XAML texts are translated as windows load (UiText in the app).
/// </summary>
public static class L
{
    private static Catalog _catalog = Catalog.Empty;

    /// <summary>The language in use.</summary>
    public static Language Current { get; private set; } = Languages.All[0];

    public static void Use(Language language, Catalog catalog)
    {
        ArgumentNullException.ThrowIfNull(language);
        ArgumentNullException.ThrowIfNull(catalog);
        Current = language;
        _catalog = catalog;
    }

    /// <summary>The translation of a fixed text, or the text itself.</summary>
    public static string T(string english) =>
        english is null ? string.Empty : _catalog.Find(english) ?? english;

    /// <summary>The translation of a text with values in it, the values filled in.</summary>
    public static string T(ref LocText text)
    {
        var template = text.Template;
        var translated = _catalog.Find(template);
        if (translated is not null)
        {
            try
            {
                return string.Format(CultureInfo.CurrentCulture, translated, text.Values);
            }
            catch (FormatException)
            {
                // A broken translation: fall back to English rather than fail.
            }
        }

        return string.Format(CultureInfo.CurrentCulture, template, text.Values);
    }

    /// <summary>The {0}, {1:N0}... a text uses, by number, for checking translations.</summary>
    public static IReadOnlySet<int> Placeholders(string format)
    {
        ArgumentNullException.ThrowIfNull(format);
        var found = new HashSet<int>();
        for (var i = 0; i < format.Length; i++)
        {
            if (format[i] == '{')
            {
                if (i + 1 < format.Length && format[i + 1] == '{')
                {
                    i++;
                    continue;
                }

                var end = i + 1;
                while (end < format.Length && char.IsAsciiDigit(format[end]))
                {
                    end++;
                }

                if (end > i + 1 && int.TryParse(format.AsSpan(i + 1, end - i - 1), NumberStyles.None, CultureInfo.InvariantCulture, out var n))
                {
                    found.Add(n);
                }
            }
        }

        return found;
    }
}

/// <summary>
/// Collects an interpolated string as a format template ("Allowed {0} for {1:N0} minutes.") and
/// its values, so <see cref="L.T(ref LocText)"/> can translate the template.
/// </summary>
[InterpolatedStringHandler]
public ref struct LocText
{
    private readonly StringBuilder _template;
    private readonly List<object?> _values;

    public LocText(int literalLength, int formattedCount)
    {
        _template = new StringBuilder(literalLength + (formattedCount * 4));
        _values = new List<object?>(formattedCount);
    }

    public readonly string Template => _template.ToString();

    public readonly object?[] Values => [.. _values];

    public readonly void AppendLiteral(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        _template.Append(text.Replace("{", "{{", StringComparison.Ordinal).Replace("}", "}}", StringComparison.Ordinal));
    }

    public readonly void AppendFormatted<T>(T value) => Add(value, null, null);

    public readonly void AppendFormatted<T>(T value, string? format) => Add(value, null, format);

    public readonly void AppendFormatted<T>(T value, int alignment) => Add(value, alignment, null);

    public readonly void AppendFormatted<T>(T value, int alignment, string? format) => Add(value, alignment, format);

    private readonly void Add(object? value, int? alignment, string? format)
    {
        _template.Append('{').Append(_values.Count.ToString(CultureInfo.InvariantCulture));
        if (alignment is { } a)
        {
            _template.Append(',').Append(a.ToString(CultureInfo.InvariantCulture));
        }

        if (!string.IsNullOrEmpty(format))
        {
            _template.Append(':').Append(format);
        }

        _template.Append('}');
        _values.Add(value);
    }
}
