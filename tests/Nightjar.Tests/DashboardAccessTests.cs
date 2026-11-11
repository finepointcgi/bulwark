using Nightjar.Web;

namespace Nightjar.Tests;

public sealed class DashboardAccessTests
{
    [Theory]
    [InlineData("http://localhost:5000", true)]
    [InlineData("http://127.0.0.1:5000;http://[::1]:5000", true)]
    [InlineData("http://0.0.0.0:5000", false)]
    [InlineData("http://*:5000", false)]
    [InlineData("http://+:80", false)]
    [InlineData("http://myhost.example:5000", false)]
    [InlineData("http://localhost:5000;http://0.0.0.0:8080", false)]
    public void Only_loopback_bindings_are_open_without_a_token(string urls, bool expected) =>
        Assert.Equal(expected, DashboardAccess.AllLoopback(urls));

    [Fact]
    public void Token_comparison_is_exact() 
    {
        Assert.True(DashboardAccess.TokenMatches("s3cret", "s3cret"));
        Assert.False(DashboardAccess.TokenMatches("s3cret", "s3cre"));
        Assert.False(DashboardAccess.TokenMatches("s3cret", null));
    }
}
