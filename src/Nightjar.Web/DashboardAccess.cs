using System.Security.Cryptography;
using System.Text;

namespace Nightjar.Web;

/// <summary>
/// Token gate for the dashboard. The token is accepted as <c>Authorization: Bearer</c>, a <c>nightjar_token</c> cookie,
/// or <c>?token=</c> on the first visit (which sets the cookie and redirects to a URL without it).
/// </summary>
public static class DashboardAccess
{
    private const string CookieName = "nightjar_token";

    public static bool AllLoopback(string urls) =>
        urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).All(url =>
            Uri.TryCreate(url.Replace("*", "example").Replace("+", "example"), UriKind.Absolute, out var uri)
            && !url.Contains('*') && !url.Contains('+')
            && (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)));

    public static bool TokenMatches(string expected, string? supplied) =>
        supplied is not null && CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(supplied)));

    public static Func<HttpContext, Func<Task>, Task> Middleware(string token) => async (context, next) =>
    {
        var request = context.Request;
        var bearer = request.Headers.Authorization.ToString() is { } header && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..] : null;
        if (TokenMatches(token, bearer) || TokenMatches(token, request.Cookies[CookieName]))
        {
            await next();
            return;
        }

        if (HttpMethods.IsGet(request.Method) && TokenMatches(token, request.Query["token"]))
        {
            context.Response.Cookies.Append(CookieName, token, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Strict, Secure = request.IsHttps });
            context.Response.Redirect(request.Path.HasValue ? request.Path.Value! : "/");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Nightjar dashboard: access token required.");
    };
}
