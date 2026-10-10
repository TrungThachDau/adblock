using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using AdblockEngine.Ipc;
using AdblockEngine.Rules;
using AdblockEngine.WinDivert;

namespace AdblockEngine;

public sealed class PacketFilterWorker : BackgroundService
{
    private readonly RuleStore _rules;
    private readonly NamedPipeServer _ipc;

    public PacketFilterWorker(RuleStore rules, NamedPipeServer ipc)
    {
        _rules = rules;
        _ipc = ipc;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        return Task.Factory.StartNew(() =>
        {
            var loop = new PacketLoop(_rules, _ipc);
            loop.Run(stoppingToken);
        }, stoppingToken, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
}

public sealed class IpcServerWorker : BackgroundService
{
    private readonly NamedPipeServer _ipc;

    public IpcServerWorker(NamedPipeServer ipc)
    {
        _ipc = ipc;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await _ipc.StartAsync(stoppingToken);
    }
}

public sealed class StatsBroadcastWorker : BackgroundService
{
    private readonly NamedPipeServer _ipc;

    public StatsBroadcastWorker(NamedPipeServer ipc)
    {
        _ipc = ipc;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var lastStats = _ipc.GetStats();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(2000, stoppingToken);
                var current = _ipc.GetStats();
                if (current.DnsQueries != lastStats.DnsQueries ||
                    current.TlsQueries != lastStats.TlsQueries ||
                    current.QuicDropped != lastStats.QuicDropped)
                {
                    _ipc.BroadcastStatsUpdate();
                    lastStats = current;
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}

public class Program
{
    public const string ServiceName = "AdblockEngine";
    public const string ServiceDisplayName = "Adblock Filtering Engine (WinDivert 2.x)";

    public static async Task<int> Main(string[] args)
    {
        // 1. Service Management Commands
        if (args.Any(a => a == "--install"))
        {
            return InstallService();
        }
        if (args.Any(a => a == "--uninstall"))
        {
            return UninstallService();
        }
        if (args.Any(a => a == "--start"))
        {
            return StartService();
        }
        if (args.Any(a => a == "--stop"))
        {
            return StopService();
        }

        bool isServiceExplicit = args.Any(a => a == "--service");
        bool isConsoleExplicit = args.Any(a => a == "--console" || a == "-c");
        bool isWindowsService = !isConsoleExplicit && (isServiceExplicit || WindowsServiceHelpers.IsWindowsService());

        if (!isWindowsService)
        {
            Console.WriteLine("==========================================");
            Console.WriteLine(" Adblock Engine (WinDivert 2.x) - C# .NET ");
            Console.WriteLine(" Mode: Console (Debug / Interactive)      ");
            Console.WriteLine("==========================================");
        }

        var ruleStore = new RuleStore();
        var ipcServer = new NamedPipeServer(ruleStore);

        // Parse optional --rules argument or try candidates
        string? specifiedRulesPath = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--rules" && i + 1 < args.Length)
            {
                specifiedRulesPath = args[i + 1];
                break;
            }
        }

        string[] candidates = specifiedRulesPath != null
            ? [specifiedRulesPath, "../spec/test-data/rules.txt", "spec/testdata/sample_list.txt", "spec/test-data/rules.txt", @"C:\ProgramData\Adblock\rules.txt"]
            : ["../spec/test-data/rules.txt", "spec/testdata/sample_list.txt", "spec/test-data/rules.txt", @"C:\ProgramData\Adblock\rules.txt"];

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                int loaded = ruleStore.LoadFile(candidate);
                Console.WriteLine($"[Rules] Loaded {loaded} rules from {candidate}");
                break;
            }
        }

        var builder = Host.CreateApplicationBuilder(args);

        if (isWindowsService)
        {
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = ServiceName;
            });
        }

        builder.Services.AddSingleton(ruleStore);
        builder.Services.AddSingleton(ipcServer);

        builder.Services.AddHostedService<PacketFilterWorker>();
        builder.Services.AddHostedService<IpcServerWorker>();
        builder.Services.AddHostedService<StatsBroadcastWorker>();

        var app = builder.Build();

        if (!isWindowsService)
        {
            Console.WriteLine("[Engine] Running and ready. Press Ctrl+C to shut down.");
        }

        await app.RunAsync();

        if (!isWindowsService)
        {
            Console.WriteLine("[Engine] Engine successfully stopped.");
        }

        return 0;
    }

    private static int RunProcess(string file, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo(file, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            string outStr = p?.StandardOutput.ReadToEnd() ?? "";
            string errStr = p?.StandardError.ReadToEnd() ?? "";
            if (!string.IsNullOrWhiteSpace(outStr)) Console.WriteLine(outStr.Trim());
            if (!string.IsNullOrWhiteSpace(errStr)) Console.Error.WriteLine(errStr.Trim());
            return p?.ExitCode ?? -1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to execute '{file} {arguments}': {ex.Message}");
            return -1;
        }
    }

    private static int InstallService()
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            Console.Error.WriteLine("Cannot determine current process executable path.");
            return -1;
        }

        string binPath = $"\"{exePath}\" --service";
        int res = RunProcess("sc.exe", $"create \"{ServiceName}\" binPath= \"{binPath}\" DisplayName= \"{ServiceDisplayName}\" start= auto");
        if (res == 0)
        {
            Console.WriteLine($"Service '{ServiceName}' installed successfully.");
        }
        return res;
    }

    private static int UninstallService()
    {
        RunProcess("sc.exe", $"stop \"{ServiceName}\"");
        int res = RunProcess("sc.exe", $"delete \"{ServiceName}\"");
        if (res == 0)
        {
            Console.WriteLine($"Service '{ServiceName}' uninstalled successfully.");
        }
        return res;
    }

    private static int StartService()
    {
        int res = RunProcess("sc.exe", $"start \"{ServiceName}\"");
        if (res == 0)
        {
            Console.WriteLine($"Service '{ServiceName}' started.");
        }
        return res;
    }

    private static int StopService()
    {
        int res = RunProcess("sc.exe", $"stop \"{ServiceName}\"");
        if (res == 0)
        {
            Console.WriteLine($"Service '{ServiceName}' stopped.");
        }
        return res;
    }
}
