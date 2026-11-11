using System.Net;
using System.Text.Json;
using Nightjar.Core.Updates;
using Nightjar.Engines.Execution;

namespace Nightjar.Tests;

public sealed class BaseImageTests : IDisposable
{
    private static readonly string DigestA = "sha256:" + new string('a', 64);
    private static readonly string DigestB = "sha256:" + new string('b', 64);
    private readonly string _dir = Directory.CreateTempSubdirectory("nightjar-base-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Theory]
    [InlineData("python:3.12-slim", "library/python", "3.12-slim", null)]
    [InlineData("golang:1.26.11-alpine", "library/golang", "1.26.11-alpine", null)]
    [InlineData("alpine", "library/alpine", "latest", null)]
    [InlineData("anchore/syft:v1.18.1", "anchore/syft", "v1.18.1", null)]
    [InlineData("docker.io/library/debian:bookworm-slim", "library/debian", "bookworm-slim", null)]
    [InlineData("mirror.gcr.io/library/alpine:3.24.4@sha256:abc", "library/alpine", "3.24.4", "sha256:abc")]
    public void Docker_hub_references_parse(string image, string repository, string tag, string? digest) =>
        Assert.Equal(new BaseImageRef(repository, tag, digest), BaseImageWatcher.Parse(image));

    [Theory]
    [InlineData("ghcr.io/aquasecurity/trivy:0.76.1")]
    [InlineData("localhost:5000/tool:1")]
    [InlineData("quay.io/org/img:2")]
    public void Other_registries_are_left_alone(string image) =>
        Assert.Null(BaseImageWatcher.Parse(image));

    [Theory]
    [InlineData("docker.io/anchore/syft:v1.18.1", "mirror.gcr.io/anchore/syft:v1.18.1")]
    [InlineData("docker.io/zaproxy/zap-stable@sha256:abc", "mirror.gcr.io/zaproxy/zap-stable@sha256:abc")]
    [InlineData("alpine:3.24.4", "mirror.gcr.io/library/alpine:3.24.4")]
    [InlineData("ghcr.io/google/osv-scanner:v2.0.0", null)]
    [InlineData("mirror.gcr.io/library/alpine:3", null)]
    public void Rate_limited_pulls_map_to_the_mirror(string reference, string? expected) =>
        Assert.Equal(expected, EngineImages.MirrorReference(reference));

    [Fact]
    public async Task Watcher_moves_to_newest_mature_patch_and_pins_every_from_line()
    {
        var dockerfile = Path.Combine(_dir, "Dockerfile");
        File.WriteAllText(dockerfile, """
            ARG BASE=debian
            FROM golang:1.26.11-alpine AS build
            RUN go build
            FROM alpine:3.24.2 AS templates
            FROM ${BASE}:bookworm-slim AS argbased
            FROM build AS again
            FROM alpine:3.24.2
            COPY --from=build /app /app
            """);

        var now = DateTimeOffset.UtcNow;
        using var http = new HttpClient(new FakeRegistry(request =>
        {
            var url = request.RequestUri!.ToString();
            if (url.Contains("hub.docker.com") && url.Contains("library/alpine"))
            {
                return Json(Tag("3.24.2", now.AddDays(-30)), Tag("3.24.3", now.AddDays(-10)), Tag("3.24.4", now.AddHours(-5)),
                    Tag("3.24.3-rc1", now.AddDays(-20)), Tag("3.25.0", now.AddDays(-40)));
            }

            if (url.Contains("hub.docker.com"))
            {
                return Json(Tag("1.26.11-alpine", now.AddDays(-9)), Tag("1.26.12", now.AddDays(-9)));
            }

            var digest = url.Contains("alpine/manifests/3.24.3") ? DigestB : DigestA;
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.Add("Docker-Content-Digest", digest);
            return response;
        }));

        var changes = await new BaseImageWatcher(http, TimeSpan.FromDays(2)).CheckAsync("tool", dockerfile, write: true, CancellationToken.None);

        var lines = File.ReadAllLines(dockerfile);
        Assert.Equal($"FROM mirror.gcr.io/library/golang:1.26.11-alpine@{DigestA} AS build", lines[1]);  // 1.26.12 is a different variant
        Assert.Equal($"FROM mirror.gcr.io/library/alpine:3.24.3@{DigestB} AS templates", lines[3]);       // 3.24.4 too new, 3.25 other minor, rc skipped
        Assert.Equal("FROM ${BASE}:bookworm-slim AS argbased", lines[4]);                                   // ARG-based: untouched
        Assert.Equal("FROM build AS again", lines[5]);                                                     // earlier stage: untouched
        Assert.Equal($"FROM mirror.gcr.io/library/alpine:3.24.3@{DigestB}", lines[6]);
        Assert.Equal(2, changes.Count); // the repeated alpine line is reported once

        // Idempotent: a second pass finds nothing.
        Assert.Empty(await new BaseImageWatcher(http, TimeSpan.FromDays(2)).CheckAsync("tool", dockerfile, write: true, CancellationToken.None));
    }

    private static object Tag(string name, DateTimeOffset pushed) => new { name, tag_last_pushed = pushed };

    private static HttpResponseMessage Json(params object[] tags) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(new { results = tags })) };

    private sealed class FakeRegistry(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // No credentials may ever be sent to registries.
            Assert.Null(request.Headers.Authorization);
            return Task.FromResult(respond(request));
        }
    }
}
