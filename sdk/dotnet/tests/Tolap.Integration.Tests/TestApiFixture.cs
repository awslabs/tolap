using System.Diagnostics;
using System.Net.Sockets;
using Xunit;

namespace Tolap.Integration.Tests;

/// <summary>
/// Launches tools/test-api/server.py as a child process for the duration of a test class.
/// </summary>
/// <remarks>
/// <para>
/// The other HTTP suites mock the transport in-process, which never puts bytes on a
/// socket. That cannot exercise a real status line, real response headers, a chunked
/// body, or a genuinely nested JSON document — so a wrapper that mishandles any of them
/// looks correct under the mocks. This fixture closes that gap without reaching the public
/// internet: the only tests that previously used the network hit api.fda.gov to refresh
/// fixtures, which mutates the repository and fails whenever the internet or the FDA is
/// unavailable.
/// </para>
/// <para>
/// Sets <see cref="Ready"/> to false rather than throwing when the port cannot be bound or
/// python3 is unavailable, matching <see cref="PostgresFixture"/>: a developer without the
/// dependency gets skipped tests, not a red suite. Port 8890 avoids the 8888/8889 the
/// Python and TypeScript suites use, so all three can run concurrently.
/// </para>
/// <para>
/// Shared through <see cref="TestApiCollection"/> rather than <c>IClassFixture</c> because
/// a single TCP port is a process-wide resource. With a per-class fixture each class got
/// its own instance: two of them raced to bind 8890, the loser exited with EADDRINUSE and
/// silently skipped its whole class, and whichever class finished first killed the server
/// the other was still using. The symptom was subtle — the suite still reported every test
/// as passing, because a skip is an early return, while the code under test had actually
/// been executed zero times. A collection fixture is constructed once and disposed after
/// every class in the collection has finished.
/// </para>
/// </remarks>
public sealed class TestApiFixture : IAsyncLifetime, IDisposable
{
    private const int Port = 8890;

    private Process? _process;

    /// <summary>
    /// Whether the server is listening and answering /healthz.
    /// </summary>
    public bool Ready { get; private set; }

    /// <summary>
    /// Base address of the running server.
    /// </summary>
    public Uri BaseAddress { get; } = new($"http://127.0.0.1:{Port}/");

    /// <summary>
    /// Why the fixture is unavailable, for a skip message.
    /// </summary>
    public string? SkipReason { get; private set; }

    public async Task InitializeAsync()
    {
        var script = Path.Combine(ScenarioHelpers.RepoRoot, "tools", "test-api", "server.py");
        if (!File.Exists(script))
        {
            SkipReason = $"test API server not found at {script}";
            return;
        }

        // An already-listening server (a developer running it by hand, or a sibling
        // suite) is reused rather than fought over.
        if (await ProbeAsync())
        {
            Ready = true;
            return;
        }

        try
        {
            _process = Process.Start(new ProcessStartInfo("python3")
            {
                ArgumentList = { script, "--port", Port.ToString() },
                WorkingDirectory = ScenarioHelpers.RepoRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            });
        }
        catch (Exception exception)
        {
            SkipReason = $"could not start python3: {exception.Message}";
            return;
        }

        if (_process is null)
        {
            SkipReason = "could not start the test API server process";
            return;
        }

        // Poll rather than sleeping a fixed interval: the server binds in a few
        // milliseconds locally but a loaded CI host is slower, and a fixed sleep is
        // either flaky or wasteful.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            if (_process.HasExited)
            {
                var stderr = await _process.StandardError.ReadToEndAsync();
                SkipReason = $"test API server exited with {_process.ExitCode}: {stderr.Trim()}";
                return;
            }

            if (await ProbeAsync())
            {
                Ready = true;
                return;
            }

            await Task.Delay(100);
        }

        SkipReason = $"test API server did not answer /healthz on port {Port} within 15s";
    }

    private async Task<bool> ProbeAsync()
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            var response = await client.GetAsync(new Uri(BaseAddress, "healthz"));
            return response.IsSuccessStatusCode;
        }
        catch (Exception exception) when (exception is HttpRequestException
                                              or TaskCanceledException
                                              or SocketException)
        {
            return false;
        }
    }

    /// <summary>
    /// An <see cref="HttpClient"/> pointed at the running server.
    /// </summary>
    public HttpClient CreateClient() => new() { BaseAddress = BaseAddress, Timeout = TimeSpan.FromSeconds(10) };

    public Task DisposeAsync()
    {
        Shutdown();
        return Task.CompletedTask;
    }

    public void Dispose() => Shutdown();

    private void Shutdown()
    {
        if (_process is null)
            return;

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
        }
        catch (InvalidOperationException)
        {
            // Already exited and reaped; nothing to clean up.
        }
        finally
        {
            _process.Dispose();
            _process = null;
        }
    }
}

/// <summary>
/// Groups every test class that needs the local test API so they share one server
/// instance and do not run concurrently with each other.
/// </summary>
[CollectionDefinition(Name)]
public sealed class TestApiCollection : ICollectionFixture<TestApiFixture>
{
    public const string Name = "test-api";
}
