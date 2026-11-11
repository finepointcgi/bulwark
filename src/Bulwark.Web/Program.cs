using Bulwark.Core.Reports;
using Bulwark.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Same location the CLI writes to (BULWARK_HOME, default ~/.bulwark).
var bulwarkHome = Bulwark.Core.Updates.ManifestStore.Default().HomeDirectory;
builder.Services.AddSingleton(new ReportArchive(bulwarkHome));
builder.Services.AddSingleton(new Bulwark.Core.Triage.TriageStore(bulwarkHome));
builder.Services.AddSingleton(new ScanHistory(bulwarkHome));
builder.Services.AddHostedService<Bulwark.Web.MonitorService>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

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
