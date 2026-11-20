using System.Net;
using System.Net.Sockets;
using CrioFire.Core;

namespace CrioFire.Tests;

public class NetEventFeedTests
{
    private static readonly DateTime Now = new(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

    private static BlockedConnection Blocked(int n, DateTime? time = null) =>
        new(time ?? Now.AddSeconds(n), @"C:\Apps\a.exe", ProtocolType.Tcp, null, new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443), (ulong)n, null);

    private static AllowedConnection Allowed(int n) =>
        new(Now.AddSeconds(n), @"C:\Apps\a.exe", ProtocolType.Tcp, null, new IPEndPoint(IPAddress.Parse("203.0.113.5"), 443), TrafficDirection.Outbound, false, (ulong)n, null);

    [Fact]
    public void WhatWasDeliveredIsTakenOnceInOrder()
    {
        var feed = new NetEventFeed();
        feed.Add(Blocked(1));
        feed.Add(Allowed(2));
        feed.Add(Blocked(3));

        Assert.Equal(new ulong[] { 1, 3 }, feed.TakeBlocked().Select(b => b.FilterId).ToArray());
        Assert.Empty(feed.TakeBlocked());
        Assert.Single(feed.TakeAllowed());
        Assert.Empty(feed.TakeAllowed());
        Assert.Equal(3, feed.Received);
    }

    [Fact]
    public void NothingGrowsWithoutLimitWhenNobodyCollects()
    {
        var feed = new NetEventFeed();
        for (var n = 0; n < NetEventFeed.MaxWaiting + 500; n++)
        {
            feed.Add(Blocked(n, Now));
            feed.Add(Allowed(n));
        }

        var blocked = feed.TakeBlocked();
        Assert.Equal(NetEventFeed.MaxWaiting, blocked.Count);
        Assert.Equal(500UL, blocked[0].FilterId);   // the oldest made room
        Assert.Equal(NetEventFeed.MaxWaiting, feed.TakeAllowed().Count);
        Assert.Equal(NetEventFeed.MaxRecent, feed.Recent(DateTime.MinValue).Count);
    }

    [Fact]
    public void RecentBlockedConnectionsStayForAnHourForTheAppsAlerts()
    {
        var feed = new NetEventFeed();
        feed.Add(Blocked(1, Now.AddMinutes(-90)));
        feed.Add(Blocked(2, Now.AddMinutes(-30)));
        feed.Add(Blocked(3, Now));

        feed.TakeBlocked();   // the service's round takes them; the app can still ask
        Assert.Equal(new ulong[] { 2, 3 }, feed.Recent(Now.AddHours(-2)).Select(b => b.FilterId).ToArray());
        Assert.Equal(new ulong[] { 3 }, feed.Recent(Now.AddMinutes(-1)).Select(b => b.FilterId).ToArray());
    }

    [Fact]
    public void AllowedConnectionsAreNotKeptWhileTheyAreNotRecorded()
    {
        var feed = new NetEventFeed { KeepAllowed = false };
        feed.Add(Allowed(1));

        Assert.Empty(feed.TakeAllowed());
        Assert.Equal(1, feed.Received);
    }
}
