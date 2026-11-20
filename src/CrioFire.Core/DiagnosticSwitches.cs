namespace CrioFire.Core;

/// <summary>
/// For finding the cause of a problem on one PC: parts of the service that can be left out,
/// one word per line in %ProgramData%\criofire\diagnostics.txt (administrators only can write
/// there). Read when the service starts; with no such file everything runs.
///   no-subscription  ask Windows for connections every round instead of having them delivered
///   no-usage         do not count the data each program uses
///   no-names         do not follow name lookups (domain rules stop working)
/// </summary>
public static class DiagnosticSwitches
{
    public const string NoSubscription = "no-subscription";
    public const string NoUsage = "no-usage";
    public const string NoNames = "no-names";

    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "criofire", "diagnostics.txt");

    /// <summary>The words in the file, lower case; empty when there is no file or it cannot be read.</summary>
    public static IReadOnlySet<string> Load(string? path = null)
    {
        try
        {
            return File.ReadAllLines(path ?? DefaultPath)
                .Select(l => l.Trim().ToLowerInvariant())
                .Where(l => l.Length > 0 && !l.StartsWith('#'))
                .ToHashSet(StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }
    }

    public static bool Has(string word) => Load().Contains(word);
}
