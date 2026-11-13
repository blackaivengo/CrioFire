using CrioFire.Service;

// criofire-svc.exe: the privileged Windows service (service name "criofire").
// FirewallWorker logs blocked connections; ApiService serves the local API on \\.\pipe\criofire;
// DomainService keeps domain rules' address filters in step with name lookups;
// UsageService counts data used per program.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "criofire");
builder.Services.AddHostedService<FirewallWorker>();
builder.Services.AddHostedService<ApiService>();
builder.Services.AddHostedService<DomainService>();
builder.Services.AddHostedService<UsageService>();

var host = builder.Build();
host.Run();
