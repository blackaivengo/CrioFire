using CrioFire.Service;

// criofire-svc.exe: the privileged Windows service (service name "criofire").
// FirewallWorker logs blocked connections; ApiService serves the local API on \\.\pipe\criofire.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "criofire");
builder.Services.AddHostedService<FirewallWorker>();
builder.Services.AddHostedService<ApiService>();

var host = builder.Build();
host.Run();
