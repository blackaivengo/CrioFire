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

public class NetEventLayoutTests
{
    [Fact]
    public void NetEventStructsMatchWindowsSdk()
    {
        Assert.Equal(8, Unsafe.SizeOf<FILETIME>());
        Assert.Equal(16, Unsafe.SizeOf<FWP_ADDR_UNION>());
        Assert.Equal(88, Unsafe.SizeOf<FWPM_NET_EVENT_HEADER0>());
        Assert.Equal(104, Unsafe.SizeOf<FWPM_NET_EVENT0>());
        Assert.Equal(16, Unsafe.SizeOf<FWPM_NET_EVENT_CLASSIFY_DROP0>());
        Assert.Equal(32, Unsafe.SizeOf<FWPM_NET_EVENT_ENUM_TEMPLATE0>());
    }

    [Theory]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.flags), 8)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.ipVersion), 12)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.ipProtocol), 16)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.localAddr), 20)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.remoteAddr), 36)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.localPort), 52)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.remotePort), 54)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.scopeId), 56)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.appId), 64)]
    [InlineData(nameof(FWPM_NET_EVENT_HEADER0.userId), 80)]
    public void HeaderFieldOffsetsMatchWindowsSdk(string field, int offset) =>
        Assert.Equal(offset, Marshal.OffsetOf<FWPM_NET_EVENT_HEADER0>(field).ToInt32());

    [Fact]
    public void EventAndTemplateOffsets()
    {
        Assert.Equal(88, Marshal.OffsetOf<FWPM_NET_EVENT0>(nameof(FWPM_NET_EVENT0.type)).ToInt32());
        Assert.Equal(96, Marshal.OffsetOf<FWPM_NET_EVENT0>(nameof(FWPM_NET_EVENT0.details)).ToInt32());
        Assert.Equal(8, Marshal.OffsetOf<FWPM_NET_EVENT_CLASSIFY_DROP0>(nameof(FWPM_NET_EVENT_CLASSIFY_DROP0.layerId)).ToInt32());
        Assert.Equal(16, Marshal.OffsetOf<FWPM_NET_EVENT_ENUM_TEMPLATE0>(nameof(FWPM_NET_EVENT_ENUM_TEMPLATE0.numFilterConditions)).ToInt32());
        Assert.Equal(24, Marshal.OffsetOf<FWPM_NET_EVENT_ENUM_TEMPLATE0>(nameof(FWPM_NET_EVENT_ENUM_TEMPLATE0.filterCondition)).ToInt32());
    }

    [Fact]
    public void FileTimeRoundTrips()
    {
        var t = new DateTime(2026, 11, 9, 20, 30, 15, DateTimeKind.Utc).AddTicks(1234567);
        Assert.Equal(t, FILETIME.FromDateTime(t).ToDateTime());
    }
}
