using System.Net;
using Auth.Application.Abstractions;
using Auth.Infrastructure.Options;
using Auth.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Auth.UnitTests.Security;

public sealed class HibpPasswordBreachCheckerTests
{
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    private const string Prefix = "5BAA6";
    private const string Suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private sealed class FakeHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return respond(request);
        }
    }

    private static (HibpPasswordBreachChecker Checker, FakeHandler Handler) Create(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond, int minCount = 1)
    {
        var handler = new FakeHandler(respond);
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var checker = new HibpPasswordBreachChecker(http, MsOptions.Create(new HibpOptions { MinBreachCount = minCount }), NullLogger<HibpPasswordBreachChecker>.Instance);
        return (checker, handler);
    }

    private static Task<HttpResponseMessage> Body(string body) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });

    [Fact]
    public async Task Sends_only_the_hash_prefix_with_padding_header()
    {
        var (checker, handler) = Create(_ => Body("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"));

        await checker.CheckAsync("password", default);

        var request = handler.Requests.ShouldHaveSingleItem();
        request.RequestUri!.AbsolutePath.ShouldBe($"/range/{Prefix}");
        request.RequestUri.ToString().ShouldNotContain(Suffix);
        request.Headers.GetValues("Add-Padding").ShouldBe(["true"]);
    }

    [Fact]
    public async Task Detects_a_breached_password()
    {
        var (checker, _) = Create(_ => Body($"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{Suffix}:9545824\r\n"));

        (await checker.CheckAsync("password", default)).ShouldBe(BreachCheckStatus.Breached);
    }

    [Fact]
    public async Task Suffix_not_present_means_not_breached()
    {
        var (checker, _) = Create(_ => Body("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"));

        (await checker.CheckAsync("password", default)).ShouldBe(BreachCheckStatus.NotBreached);
    }

    [Fact]
    public async Task Padding_entries_with_zero_count_are_ignored()
    {
        var (checker, _) = Create(_ => Body($"{Suffix}:0\r\n"));

        (await checker.CheckAsync("password", default)).ShouldBe(BreachCheckStatus.NotBreached);
    }

    [Fact]
    public async Task Respects_minimum_breach_count()
    {
        var (checker, _) = Create(_ => Body($"{Suffix}:3\r\n"), minCount: 10);

        (await checker.CheckAsync("password", default)).ShouldBe(BreachCheckStatus.NotBreached);
    }

    [Fact]
    public async Task Server_error_timeout_or_network_failure_report_unavailable()
    {
        (await Create(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))).Checker.CheckAsync("password", default))
            .ShouldBe(BreachCheckStatus.Unavailable);
        (await Create(_ => throw new HttpRequestException("down")).Checker.CheckAsync("password", default))
            .ShouldBe(BreachCheckStatus.Unavailable);
        (await Create(_ => throw new TaskCanceledException("timeout")).Checker.CheckAsync("password", default))
            .ShouldBe(BreachCheckStatus.Unavailable);
    }
}
