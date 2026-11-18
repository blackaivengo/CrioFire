using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CrioFire.App.Pages;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// "Program details": a program's Authenticode signature (who signed it, whether the signature
/// still holds), what its file says about it, its size, date and SHA-256; with buttons to open its
/// folder, search the web for it and look its hash up on VirusTotal. Opened from an Ask-mode alert,
/// a row's menu and the details window.
/// </summary>
public partial class ProgramInfoWindow : Window
{
    private readonly AppModel _model;
    private readonly string _app;
    private readonly List<Fact> _facts = [];
    private FileVersionInfo? _version;
    private string? _sha256;

    private ProgramInfoWindow(AppModel model, string app)
    {
        _model = model;
        _app = app;
        InitializeComponent();
        TitleText.Text = Path.GetFileName(app) is { Length: > 0 } name ? name : app;
        PathText.Text = app;
        var exists = File.Exists(app);
        FolderButton.IsEnabled = exists;
        SearchButton.IsEnabled = !KnownApps.IsKernel(app);
        MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed && e.OriginalSource is not Button and not TextBox)
            {
                DragMove();
            }
        };

        if (!exists)
        {
            _facts.Add(new Fact(L.T("Program"), KnownApps.IsKernel(app)
                ? L.T("The Windows kernel: file and printer sharing, NetBIOS, ICMP and other system traffic.")
                : L.T($"{app} (not found on this PC any more)")));
            ShowFacts(_facts);
            return;
        }

        _facts.Add(new Fact(L.T("Signature"), L.T("Checking…")));
        ShowFacts(_facts);
        Loaded += async (_, _) => await ReadAsync();
    }

    /// <summary>Opens the details of a program; nothing happens without a path.</summary>
    internal static void Open(Window? owner, AppModel model, string? app)
    {
        if (string.IsNullOrEmpty(app))
        {
            return;
        }

        var window = new ProgramInfoWindow(model, app);
        if (owner is { IsVisible: true })
        {
            window.Owner = owner;
            window.Topmost = owner.Topmost;
        }
        else
        {
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        window.ShowDialog();
    }

    private async Task ReadAsync()
    {
        // The signature check and the hash read the whole file: off the UI thread.
        var app = _app;
        var (signature, version, file, sha256) = await Task.Run(() =>
        {
            SignatureInfo? s = null;
            try
            {
                s = AuthenticodeSignatures.Describe(app);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or DllNotFoundException)
            {
                // Shown as "could not be checked" below.
            }

            FileVersionInfo? v = null;
            FileInfo? f = null;
            string? hash = null;
            try
            {
                v = FileVersionInfo.GetVersionInfo(app);
                f = new FileInfo(app);
                using var stream = new FileStream(app, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                hash = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Partial details are still worth showing.
            }

            return (s, v, f, hash);
        });

        _version = version;
        _sha256 = sha256;
        VirusTotalButton.IsEnabled = sha256 is not null;

        var facts = new List<Fact>();
        if (signature is null)
        {
            facts.Add(new Fact(L.T("Signature"), L.T("Could not be checked.")));
        }
        else
        {
            facts.Add(new Fact(L.T("Signature"), Verdict(signature)));
            if (signature.Signer is not null)
            {
                var by = signature.Organization is { Length: > 0 } o && !o.Equals(signature.Signer, StringComparison.OrdinalIgnoreCase)
                    ? $"{signature.Signer} ({o})"
                    : signature.Signer;
                facts.Add(new Fact(L.T("Signed by"), by));
                if (signature.Issuer is { Length: > 0 } issuer)
                {
                    facts.Add(new Fact(L.T("Certificate issued by"), issuer));
                }

                if (signature.ValidFromUtc is { } from && signature.ValidToUtc is { } to)
                {
                    facts.Add(new Fact(L.T("Certificate valid"), $"{from.ToLocalTime():d} – {to.ToLocalTime():d}"));
                }

                if (signature.Thumbprint is { Length: > 0 } thumbprint)
                {
                    facts.Add(new Fact(L.T("Certificate thumbprint"), thumbprint));
                }
            }
        }

        if (version is not null)
        {
            Add(facts, L.T("Description"), version.FileDescription);
            Add(facts, L.T("Company"), version.CompanyName);
            Add(facts, L.T("Product"), version.ProductName);
            Add(facts, L.T("Version"), version.FileVersion);
            Add(facts, L.T("Original file name"), version.OriginalFilename);
        }

        if (file is not null)
        {
            facts.Add(new Fact(L.T("Size"), $"{DataSize.Text(file.Length, CultureInfo.CurrentCulture)} ({file.Length.ToString("N0", CultureInfo.CurrentCulture)} bytes)"));
            facts.Add(new Fact(L.T("Modified"), file.LastWriteTime.ToString("g", CultureInfo.CurrentCulture)));
        }

        if (sha256 is not null)
        {
            facts.Add(new Fact("SHA-256", sha256));
        }

        _facts.Clear();
        _facts.AddRange(facts);
        ShowFacts(_facts);
    }

    private static string Verdict(SignatureInfo s) => s.State switch
    {
        SignatureState.Valid => L.T("Signed, and the signature is valid"),
        SignatureState.NotSigned => L.T("Not signed (some of Windows' own programs are signed through a catalog instead)"),
        SignatureState.Tampered => L.T("Signed, but the file was changed after it was signed"),
        SignatureState.Expired => L.T("Signed with a certificate that has expired"),
        SignatureState.Revoked => L.T("Signed with a certificate that was revoked"),
        SignatureState.UntrustedRoot => L.T("Signed with a certificate Windows does not trust"),
        SignatureState.Distrusted => L.T("Signed by a publisher that is blocked on this PC"),
        _ => L.T($"The signature is not valid (error 0x{s.Result:X8})"),
    };

    private static void Add(List<Fact> facts, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            facts.Add(new Fact(label, value.Trim()));
        }
    }

    private void ShowFacts(List<Fact> facts) => Facts.ItemsSource = facts.ToList();

    private void OnFolder(object sender, RoutedEventArgs e) => RowMenu.OpenFolder(_app);

    private void OnSearch(object sender, RoutedEventArgs e) =>
        RowMenu.Browse(NetworkTools.SearchUrl(Path.GetFileName(_app), _version?.FileDescription, _version?.CompanyName));

    private void OnVirusTotal(object sender, RoutedEventArgs e)
    {
        if (_sha256 is not null)
        {
            RowMenu.Browse(NetworkTools.VirusTotalUrl(_sha256));
        }
    }

    private void OnCopy(object sender, RoutedEventArgs e) => RowMenu.Copy(_model, ConnectionFacts.AsText(TitleText.Text, _app, _facts));
}
