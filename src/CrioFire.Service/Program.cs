using CrioFire.Service;

// criofire-svc.exe: the privileged Windows service (service name "criofire").
// Phase 1 adds the local API named pipe (\\.\pipe\criofire) and the WFP net-event listener.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "criofire");
builder.Services.AddHostedService<FirewallWorker>();

var host = builder.Build();
host.Run();
