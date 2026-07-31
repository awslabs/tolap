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
/// The port is assigned by the OS rather than hard-coded: <see cref="FreePort"/> binds port
/// 0, reads the port the kernel chose, and releases it. A fixed port is a machine-wide
/// resource, and this suite used to claim 8890 — so a second copy of it, or an orphaned
/// server from a killed run, made the fixture unable to bind. Two such orphans (28 and 43
/// minutes old) once left <c>dotnet test</c> hanging indefinitely at 0% CPU waiting on
/// /healthz. An ephemeral port has no contention to lose, so that failure mode is gone
/// rather than merely less likely, and this suite no longer has to coordinate port numbers
/// with the Python and TypeScript ones.
/// </para>
/// <para>
/// <b>A failure to start is a failed suite, not a skipped one</b>, with the two exceptions
/// below. <see cref="Ready"/> used to be set to false for every failure, including "the
/// port is already taken" — so the affected tests returned early and the suite still
/// reported green while the code under test had been executed zero times. One run showed
/// the live-API tests "passing" with no hits on the wrapper at all. Skipping is the right
/// behaviour for a genuinely absent dependency; it is the wrong behaviour for a server that
/// should have started and did not, because that reads as success.
/// </para>
/// <para>
/// So <see cref="Ready"/> is false only when <c>server.py</c> is missing or <c>python3</c>
/// cannot be launched — a developer without Python gets skipped tests, matching
/// <see cref="PostgresFixture"/>. Every other outcome (the process died, or never answered
/// /healthz) throws, because with an OS-assigned port there is no benign reason for it.
/// </para>
/// <para>
/// Shared through <see cref="TestApiCollection"/> rather than <c>IClassFixture</c> so the
/// classes share one server instead of starting one each. With a per-class fixture each
/// class got its own instance, and on a fixed port they fought: the loser exited with
/// EADDRINUSE and silently skipped its whole class, and whichever class finished first
/// killed the server the other was still using. A collection fixture is constructed once
/// and disposed after every class in the collection has finished.
/// </para>
/// </remarks>
public sealed class TestApiFixture : IAsyncLifetime, IDisposable
{
    private readonly int _port = FreePort();

    private Process? _process;

    /// <summary>
    /// Whether the server is listening and answering /healthz. False only for an absent
    /// dependency; every other startup failure throws from <see cref="InitializeAsync"/>.
    /// </summary>
    public bool Ready { get; private set; }

    /// <summary>
    /// Base address of the running server.
    /// </summary>
    public Uri BaseAddress => new($"http://127.0.0.1:{_port}/");

    /// <summary>
    /// Asks the OS for an unused loopback port by binding port 0, then releases it.
    /// </summary>
    /// <remarks>
    /// Mirrors <c>_free_port()</c> in the Python suite's <c>test_live_http_api.py</c>. The
    /// port is released before the server claims it, so it is in principle possible for
    /// something else to take it in between; in practice the kernel does not hand out the
    /// same ephemeral port again that quickly, and the alternative — passing the listening
    /// socket to a child process — is not worth the complexity for a test fixture. A lost
    /// race now surfaces as a failure rather than a silent skip.
    /// </remarks>
    private static int FreePort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        return ((System.Net.IPEndPoint)socket.LocalEndPoint!).Port;
    }

    /// <summary>
    /// Why the dependency is absent, for a skip message. Set only alongside
    /// <see cref="Ready"/> being false.
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

        // No probe for an already-running server: the port came from the OS moments ago,
        // so anything answering on it is not ours and reusing it would be wrong.
        try
        {
            _process = Process.Start(new ProcessStartInfo("python3")
            {
                ArgumentList = { script, "--port", _port.ToString() },
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

        // Past this point python3 exists and the script is present, so the dependency is
        // installed and any remaining failure is real. These throw rather than skip.

        // Poll rather than sleeping a fixed interval: the server binds in a few
        // milliseconds locally but a loaded CI host is slower, and a fixed sleep is
        // either flaky or wasteful.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            if (_process.HasExited)
            {
                var stderr = await _process.StandardError.ReadToEndAsync();
                throw new InvalidOperationException(
                    $"test API server exited with {_process.ExitCode} on port {_port}: {stderr.Trim()}");
            }

            if (await ProbeAsync())
            {
                Ready = true;
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException(
            $"test API server did not answer /healthz on port {_port} within 15s");
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
