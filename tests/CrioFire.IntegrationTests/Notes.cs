namespace CrioFire.IntegrationTests;

/// <summary>
/// Findings a test wants on the run page whether it passes or not. Each becomes a file in the
/// folder named by CRIOFIRE_TEST_NOTES; build/test-report.ps1 shows them as notices.
/// </summary>
internal static class Notes
{
    public static void Write(string title, string text)
    {
        var folder = Environment.GetEnvironmentVariable("CRIOFIRE_TEST_NOTES");
        if (string.IsNullOrWhiteSpace(folder))
        {
            return;
        }

        Directory.CreateDirectory(folder);
        var name = string.Concat(title.Select(c => char.IsLetterOrDigit(c) || c is ' ' or '-' ? c : '_'));
        File.WriteAllText(Path.Combine(folder, name + ".txt"), title + "\n" + text);
    }
}
