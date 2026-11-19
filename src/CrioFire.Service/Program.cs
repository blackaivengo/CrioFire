using CrioFire.Core;
using CrioFire.Service;

// criofire-svc.exe: the privileged Windows service (service name "criofire").
// FirewallWorker logs blocked connections; ApiService serves the local API on \\.\pipe\criofire;
// DomainService keeps domain rules' address filters in step with name lookups;
// UsageService counts data used per program; UpdateService looks for a newer CrioFire once a day;
// ProtectionService guards the service itself: its files, its permissions and unexpected stops.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "criofire");
builder.Services.AddSingleton(new SelfProtection(
    AppContext.BaseDirectory, AuthenticodeSignatures.Describe, SelfProtection.DefaultMarkerPath));
builder.Services.AddHostedService<ProtectionService>();
builder.Services.AddHostedService<FirewallWorker>();
builder.Services.AddHostedService<ApiService>();
builder.Services.AddHostedService<DomainService>();
builder.Services.AddHostedService<UsageService>();
builder.Services.AddHostedService<UpdateService>();

var host = builder.Build();
host.Run();
