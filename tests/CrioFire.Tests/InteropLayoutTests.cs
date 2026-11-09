using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using CrioFire.Core.Interop;

namespace CrioFire.Tests;

/// <summary>
/// Pins the managed struct layouts to the Windows SDK's 64-bit layouts. If one of these
/// fails, WFP calls would read or write the wrong bytes: fix the struct, never the test.
/// </summary>
public class InteropLayoutTests
{
    [Fact]
    public void ProcessIs64Bit() => Assert.True(Environment.Is64BitProcess);

    [Fact]
    public void StructSizesMatchWindowsSdk()
    {
        Assert.Equal(16, Unsafe.SizeOf<FWP_BYTE_BLOB>());
        Assert.Equal(16, Unsafe.SizeOf<FWPM_DISPLAY_DATA0>());
        Assert.Equal(16, Unsafe.SizeOf<FWP_VALUE0>());
        Assert.Equal(40, Unsafe.SizeOf<FWPM_FILTER_CONDITION0>());
        Assert.Equal(20, Unsafe.SizeOf<FWPM_ACTION0>());
        Assert.Equal(64, Unsafe.SizeOf<FWPM_PROVIDER0>());
        Assert.Equal(72, Unsafe.SizeOf<FWPM_SUBLAYER0>());
        Assert.Equal(200, Unsafe.SizeOf<FWPM_FILTER0>());
    }

    [Theory]
    [InlineData(nameof(FWPM_FILTER0.filterKey), 0)]
    [InlineData(nameof(FWPM_FILTER0.displayData), 16)]
    [InlineData(nameof(FWPM_FILTER0.flags), 32)]
    [InlineData(nameof(FWPM_FILTER0.providerKey), 40)]
    [InlineData(nameof(FWPM_FILTER0.providerData), 48)]
    [InlineData(nameof(FWPM_FILTER0.layerKey), 64)]
    [InlineData(nameof(FWPM_FILTER0.subLayerKey), 80)]
    [InlineData(nameof(FWPM_FILTER0.weight), 96)]
    [InlineData(nameof(FWPM_FILTER0.numFilterConditions), 112)]
    [InlineData(nameof(FWPM_FILTER0.filterCondition), 120)]
    [InlineData(nameof(FWPM_FILTER0.action), 128)]
    [InlineData(nameof(FWPM_FILTER0.context), 152)]
    [InlineData(nameof(FWPM_FILTER0.reserved), 168)]
    [InlineData(nameof(FWPM_FILTER0.filterId), 176)]
    [InlineData(nameof(FWPM_FILTER0.effectiveWeight), 184)]
    public void FilterFieldOffsetsMatchWindowsSdk(string field, int offset) =>
        Assert.Equal(offset, Marshal.OffsetOf<FWPM_FILTER0>(field).ToInt32());

    [Theory]
    [InlineData(nameof(FWPM_SUBLAYER0.flags), 32)]
    [InlineData(nameof(FWPM_SUBLAYER0.providerKey), 40)]
    [InlineData(nameof(FWPM_SUBLAYER0.providerData), 48)]
    [InlineData(nameof(FWPM_SUBLAYER0.weight), 64)]
    public void SubLayerFieldOffsetsMatchWindowsSdk(string field, int offset) =>
        Assert.Equal(offset, Marshal.OffsetOf<FWPM_SUBLAYER0>(field).ToInt32());

    [Theory]
    [InlineData(nameof(FWPM_PROVIDER0.flags), 32)]
    [InlineData(nameof(FWPM_PROVIDER0.providerData), 40)]
    [InlineData(nameof(FWPM_PROVIDER0.serviceName), 56)]
    public void ProviderFieldOffsetsMatchWindowsSdk(string field, int offset) =>
        Assert.Equal(offset, Marshal.OffsetOf<FWPM_PROVIDER0>(field).ToInt32());
}
