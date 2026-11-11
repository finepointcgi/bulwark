using Nightjar.Core.Reports;
using Nightjar.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Same location the CLI writes to (NIGHTJAR_HOME, default ~/.nightjar).
var nightjarHome = Nightjar.Core.Updates.ManifestStore.Default().HomeDirectory;
builder.Services.AddSingleton(new ReportArchive(nightjarHome));
builder.Services.AddSingleton(new Nightjar.Core.Triage.TriageStore(nightjarHome));
builder.Services.AddSingleton(new ScanHistory(nightjarHome));
builder.Services.AddHostedService<Nightjar.Web.MonitorService>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// The dashboard shows vulnerabilities and triage controls. Bound to localhost it needs no login; bound to
// any other address it refuses to start unless NIGHTJAR_DASHBOARD_TOKEN is set, and then requires that token.
var dashboardToken = Environment.GetEnvironmentVariable("NIGHTJAR_DASHBOARD_TOKEN");
var configuredUrls = builder.Configuration["urls"] ?? builder.Configuration["ASPNETCORE_URLS"] ?? "http://localhost:5000";
if (string.IsNullOrEmpty(dashboardToken) && !Nightjar.Web.DashboardAccess.AllLoopback(configuredUrls))
{
    Console.Error.WriteLine($"error: the dashboard is configured to listen on {configuredUrls}, which is reachable from the network. Set NIGHTJAR_DASHBOARD_TOKEN to a long random value, or bind to localhost.");
    return 2;
}

var app = builder.Build();

if (!string.IsNullOrEmpty(dashboardToken))
{
    app.Use(Nightjar.Web.DashboardAccess.Middleware(dashboardToken));
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
return 0;
