using System.Security.Cryptography;
using CrioFire.Core;

namespace CrioFire.Tests;

public sealed class LicenseTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);
    private readonly ECDsa _crioSoft = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _public;
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"criofire-license-{Guid.NewGuid():N}.key");

    public LicenseTests()
    {
        _public = ECDsa.Create();
        _public.ImportFromPem(_crioSoft.ExportSubjectPublicKeyInfoPem());
    }

    public void Dispose()
    {
        _crioSoft.Dispose();
        _public.Dispose();
        File.Delete(_path);
    }

    [Fact]
    public void AnIssuedKeyChecksOut()
    {
        var key = LicenseKeys.Issue(License(seats: 25), _crioSoft);

        var status = LicenseKeys.Check(key, Now, _public);

        Assert.StartsWith("CRIOFIRE1.", key, StringComparison.Ordinal);
        Assert.Equal(LicenseStates.Valid, status.State);
        Assert.True(status.IsLicensed);
        Assert.Equal("Contoso Ltd", status.Licensee);
        Assert.Equal(25, status.Seats);
        Assert.Contains("25 computers", status.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AKeyCopiedFromAnEmailWithLineBreaksStillWorks()
    {
        var key = LicenseKeys.Issue(License(), _crioSoft);
        var wrapped = string.Join("\r\n  ", key.Chunk(40).Select(c => new string(c)));

        Assert.Equal(LicenseStates.Valid, LicenseKeys.Check(wrapped, Now, _public).State);
    }

    [Fact]
    public void AChangedKeyIsRefused()
    {
        var key = LicenseKeys.Issue(License(seats: 5), _crioSoft);
        var parts = key.Split('.');
        var forged = LicenseKeys.Issue(License(seats: 5000), ECDsa.Create(ECCurve.NamedCurves.nistP256)).Split('.')[1];

        Assert.Equal(LicenseStates.Invalid, LicenseKeys.Check($"{parts[0]}.{forged}.{parts[2]}", Now, _public).State);
        Assert.Equal(LicenseStates.Invalid, LicenseKeys.Check(key[..^4] + "AAAA", Now, _public).State);
        Assert.Equal(LicenseStates.Invalid, LicenseKeys.Check("not a key", Now, _public).State);
        Assert.Equal(LicenseStates.Invalid, LicenseKeys.Check("CRIOFIRE1.!!!.???", Now, _public).State);
    }

    [Fact]
    public void AKeyFromAnotherSignerIsRefused()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = LicenseKeys.Issue(License(), other);

        Assert.Equal(LicenseStates.Invalid, LicenseKeys.Check(key, Now, _public).State);
    }

    [Fact]
    public void ExpiryIsReportedButNeverStopsTheFirewall()
    {
        var key = LicenseKeys.Issue(License(expires: Now.AddDays(10)), _crioSoft);

        Assert.Equal(LicenseStates.Expiring, LicenseKeys.Check(key, Now, _public).State);
        Assert.True(LicenseKeys.Check(key, Now, _public).IsLicensed);
        var expired = LicenseKeys.Check(key, Now.AddDays(11), _public);
        Assert.Equal(LicenseStates.Expired, expired.State);
        Assert.False(expired.IsLicensed);
        Assert.Contains("keeps protecting", expired.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NoKeyMeansFreeUseAndNoPublicKeyMeansCannotCheck()
    {
        Assert.Equal(LicenseStates.None, LicenseKeys.Check(null, Now, _public).State);
        Assert.Equal(LicenseStates.None, LicenseKeys.Check("  ", Now, null).State);
        Assert.Equal(LicenseStates.Unavailable, LicenseKeys.Check("CRIOFIRE1.a.b", Now, null).State);
    }

    [Fact]
    public void TheKeyIsStoredCleanedAndCanBeRemoved()
    {
        var store = new LicenseStore(_path);
        Assert.Null(store.Key);

        store.Set(" CRIOFIRE1.abc\n.def ");
        Assert.Equal("CRIOFIRE1.abc.def", store.Key);

        store.Set(null);
        Assert.Null(store.Key);
    }

    private static LicenseData License(int seats = 10, DateTime? expires = null) =>
        new(LicenseKeys.CurrentFormat, "CF-20261113-ABCDEF", "Contoso Ltd", "it@contoso.example", "business", seats, Now.AddDays(-1), expires ?? Now.AddYears(1));
}
