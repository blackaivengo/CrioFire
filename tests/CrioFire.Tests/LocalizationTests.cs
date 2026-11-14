using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using CrioFire.Core;

namespace CrioFire.Tests;

/// <summary>Translating the desktop app: choosing the language, looking texts up, and the translation files themselves.</summary>
public sealed class LocalizationTests : IDisposable
{
    public void Dispose() => L.Use(Languages.All[0], Catalog.Empty);

    [Theory]
    [InlineData("system", "de-DE", "de")]
    [InlineData("system", "de-AT", "de")]
    [InlineData("system", "pt-PT", "pt-BR")]
    [InlineData("system", "pt-BR", "pt-BR")]
    [InlineData("system", "zh-CN", "zh-Hans")]
    [InlineData("system", "zh-SG", "zh-Hans")]
    [InlineData("system", "zh-TW", "en")]      // Traditional Chinese is not translated
    [InlineData("system", "es-MX", "es")]
    [InlineData("system", "ar-EG", "ar")]
    [InlineData("system", "sv-SE", "en")]
    [InlineData("ja", "de-DE", "ja")]           // the user's choice wins
    [InlineData("klingon", "fr-FR", "fr")]      // an unknown choice follows Windows
    public void TheLanguageFollowsTheChoiceThenWindows(string preference, string windows, string expected) =>
        Assert.Equal(expected, Languages.Resolve(preference, new CultureInfo(windows)).Code);

    [Fact]
    public void SixteenLanguagesWithEnglishFirst()
    {
        Assert.Equal(16, Languages.All.Count);
        Assert.Equal("en", Languages.All[0].Code);
        Assert.Equal(16, Languages.All.Select(l => l.Code).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(["ar", "ur"], Languages.All.Where(l => l.RightToLeft).Select(l => l.Code));
        Assert.All(Languages.All, l => _ = new CultureInfo(l.Code));
    }

    [Fact]
    public void TextsAreTranslatedAndValuesFilledIn()
    {
        L.Use(Languages.Find("de")!, Catalog.Parse("""
            {
              "// note": "for translators",
              "Clear history": "Verlauf löschen",
              "Allowed {0} for {1} minutes.": "{0} für {1} Minuten erlaubt.",
              "{0} of {1} done": "{1}: {0} erledigt",
              "Still to do": ""
            }
            """));
        var name = "Firefox";
        var minutes = 15;

        Assert.Equal("Verlauf löschen", L.T("Clear history"));
        Assert.Equal("Firefox für 15 Minuten erlaubt.", L.T($"Allowed {name} for {minutes} minutes."));
        Assert.Equal("10: 3 erledigt", L.T($"{3} of {10} done"));          // translators may reorder values
        Assert.Equal("Still to do", L.T("Still to do"));                    // empty: English
        Assert.Equal("Not translated", L.T("Not translated"));
        Assert.Equal("Firefox: 15", L.T($"{name}: {minutes}"));
        Assert.Equal("for translators", L.T("for translators"));            // notes are not texts
    }

    [Fact]
    public void FormatsAndBracesSurviveTranslation()
    {
        L.Use(Languages.Find("fr")!, Catalog.Parse("""{"Saved {0:N0} rules {{ok}}": "{0:N0} règles enregistrées {{ok}}", "Broken {0}": "Cassé {1}"}"""));
        var count = 1234;

        Assert.Equal(string.Format(CultureInfo.CurrentCulture, "{0:N0} règles enregistrées {{ok}}", 1234), L.T($"Saved {count:N0} rules {{ok}}"));
        Assert.Equal("Broken x", L.T($"Broken {"x"}"));                     // a broken translation falls back to English
    }

    [Theory]
    [InlineData("No values", new int[0])]
    [InlineData("{0} and {1:N0}, {{not}} {2,5}", new[] { 0, 1, 2 })]
    [InlineData("{1} before {0}", new[] { 0, 1 })]
    public void PlaceholdersAreFound(string format, int[] expected) =>
        Assert.Equal(expected.OrderBy(n => n), L.Placeholders(format).OrderBy(n => n));

    [Fact]
    public void AFileThatIsNotAnObjectIsRefused() =>
        Assert.ThrowsAny<JsonException>(() => Catalog.Parse("[\"Clear history\"]"));

    [Fact]
    public void TheEnglishListHasTheAppsTexts()
    {
        var english = Read("en");
        Assert.True(english.Count > 500, $"en.json lists only {english.Count} texts.");
        Assert.All(english, e => Assert.Equal(e.Key, e.Value));
        Assert.Contains("Clear history", english.Keys);
        Assert.Contains("Allowed {0} for {1} minutes.", english.Keys);
    }

    [Fact]
    public void EveryTranslationFitsTheEnglishText()
    {
        var english = Read("en");
        var problems = new List<string>();
        foreach (var language in Languages.All.Skip(1))
        {
            var path = Path.Combine(StringsFolder, language.Code + ".json");
            if (!File.Exists(path))
            {
                continue;   // not translated yet: the app shows English
            }

            Catalog catalog;
            try
            {
                catalog = Catalog.Parse(File.ReadAllText(path));
            }
            catch (JsonException ex)
            {
                problems.Add($"{language.Code}.json is not valid JSON: {ex.Message}");
                continue;
            }

            foreach (var (key, translation) in catalog.Texts)
            {
                if (!english.ContainsKey(key))
                {
                    problems.Add($"{language.Code}: the app has no text '{key}'");
                    continue;
                }

                var extra = L.Placeholders(translation).Except(L.Placeholders(key)).ToList();
                if (extra.Count > 0)
                {
                    problems.Add($"{language.Code}: '{translation}' uses {{{extra[0]}}}, which '{key}' does not have");
                    continue;
                }

                if (L.Placeholders(key).Count == 0)
                {
                    continue;   // shown as it is, never formatted
                }

                try
                {
                    _ = string.Format(CultureInfo.InvariantCulture, translation, Enumerable.Range(0, 10).Cast<object>().ToArray());
                }
                catch (FormatException)
                {
                    problems.Add($"{language.Code}: '{translation}' is not a valid format (write a brace that is not a value twice)");
                }
            }
        }

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems.Take(30)));
    }

    /// <summary>The installer's language for each of the app's: the culture of its installer\Strings\*.wxl.</summary>
    private static readonly Dictionary<string, string> InstallerCultures = new(StringComparer.Ordinal)
    {
        ["en"] = "en-US", ["zh-Hans"] = "zh-CN", ["hi"] = "hi-IN", ["es"] = "es-ES", ["ar"] = "ar-SA", ["fr"] = "fr-FR",
        ["bn"] = "bn-BD", ["pt-BR"] = "pt-BR", ["ru"] = "ru-RU", ["id"] = "id-ID", ["ur"] = "ur-PK", ["de"] = "de-DE",
        ["ja"] = "ja-JP", ["tr"] = "tr-TR", ["ko"] = "ko-KR", ["vi"] = "vi-VN",
    };

    [Fact]
    public void TheInstallerSpeaksEveryLanguageOfTheApp()
    {
        XNamespace wxl = "http://wixtoolset.org/schemas/v4/wxl";
        var folder = Path.Combine(RepoRoot, "installer", "Strings");
        Assert.Equal(Languages.All.Select(l => l.Code).Order(StringComparer.Ordinal), InstallerCultures.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(
            InstallerCultures.Values.Order(StringComparer.Ordinal),
            Directory.GetFiles(folder, "*.wxl").Select(Path.GetFileNameWithoutExtension).Order(StringComparer.Ordinal));

        // build/package-msi.ps1 builds and joins exactly these languages.
        var script = File.ReadAllText(Path.Combine(RepoRoot, "build", "package-msi.ps1"));
        var built = Regex.Matches(script, @"'([a-z]{2}-[A-Z]{2})' = \d+").Select(m => m.Groups[1].Value).Distinct();
        Assert.Equal(InstallerCultures.Values.Order(StringComparer.Ordinal), built.Order(StringComparer.Ordinal));

        Dictionary<string, string> Texts(string culture, List<string> problems)
        {
            var root = XDocument.Load(Path.Combine(folder, culture + ".wxl")).Root!;
            if ((string?)root.Attribute("Culture") != culture)
            {
                problems.Add($"{culture}.wxl: Culture=\"{(string?)root.Attribute("Culture")}\"");
            }

            // UTF-8 for every language: Hindi and Bengali have no other code page, and one code page lets
            // the transforms carry only texts. The summary stream must be ANSI; its texts are English.
            if ((string?)root.Attribute("Codepage") != "65001" || (string?)root.Attribute("SummaryInformationCodepage") != "1252")
            {
                problems.Add($"{culture}.wxl: Codepage must be 65001 and SummaryInformationCodepage 1252");
            }

            var texts = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var s in root.Elements(wxl + "String"))
            {
                if (!texts.TryAdd((string)s.Attribute("Id")!, (string?)s.Attribute("Value") ?? ""))
                {
                    problems.Add($"{culture}.wxl: {(string)s.Attribute("Id")!} is there twice");
                }
            }

            return texts;
        }

        static string Shape(string text) =>
            string.Join(" ", Regex.Matches(text, @"\[[A-Za-z_]+\]|\{\\WixUI_Font_[A-Za-z]+\}").Select(m => m.Value).Order(StringComparer.Ordinal));

        var problems = new List<string>();
        var english = Texts("en-US", problems);
        foreach (var culture in InstallerCultures.Values.Where(c => c != "en-US"))
        {
            var texts = Texts(culture, problems);
            foreach (var (id, englishText) in english)
            {
                if (!texts.TryGetValue(id, out var text) || text.Length == 0)
                {
                    problems.Add($"{culture}.wxl: {id} is missing");
                }
                else if (Shape(text) != Shape(englishText))
                {
                    problems.Add($"{culture}.wxl: {id} must keep {Shape(englishText)}");
                }
            }

            foreach (var (id, text) in texts)
            {
                if (Regex.Count(text.Replace("&&", "", StringComparison.Ordinal), "&") > 1)
                {
                    problems.Add($"{culture}.wxl: {id} has more than one & (the underlined letter)");
                }

                if (Regex.IsMatch(text, @"\[(?!ProductName\])[^\]]*\]"))
                {
                    problems.Add($"{culture}.wxl: {id} names a property other than [ProductName]");
                }
            }
        }

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems.Take(30)));
    }

    private static string RepoRoot
    {
        get
        {
            var dir = new DirectoryInfo(Environment.GetEnvironmentVariable("CRIOFIRE_REPO") is { Length: > 0 } repo ? repo : AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CrioFire.slnx")))
            {
                dir = dir.Parent;
            }

            return dir?.FullName ?? throw new DirectoryNotFoundException("The repository root was not found.");
        }
    }

    private static string StringsFolder => Path.Combine(RepoRoot, "src", "CrioFire.App", "Strings");

    private static Dictionary<string, string> Read(string code) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(Path.Combine(StringsFolder, code + ".json")))!;
}
