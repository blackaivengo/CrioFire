using System.Diagnostics;

namespace CrioFire.Cli;

/// <summary>The executable paths of the programs running right now (those this process may inspect).</summary>
internal static class RunningPrograms
{
    public static List<string> Paths()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path))
                    {
                        paths.Add(path);
                    }
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                {
                    // Protected or already exited: skip.
                }
            }
        }

        return [.. paths];
    }
}
