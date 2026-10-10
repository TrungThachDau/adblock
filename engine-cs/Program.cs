using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AdblockEngine.Ipc;
using AdblockEngine.Rules;
using AdblockEngine.WinDivert;

namespace AdblockEngine;

public class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("==========================================");
        Console.WriteLine(" Adblock Engine (WinDivert 2.x) - C# .NET ");
        Console.WriteLine("==========================================");

        var ruleStore = new RuleStore();
        var ipcServer = new NamedPipeServer(ruleStore);
        using var cts = new CancellationTokenSource();

        Console.CancelKeyPress += (sender, eventArgs) =>
        {
            eventArgs.Cancel = true;
            Console.WriteLine("\n[Shutdown] Cancellation received. Stopping engine...");
            cts.Cancel();
        };

        // Parse CLI arguments
        string rulesPath = "../spec/test-data/rules.txt";
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--rules" && i + 1 < args.Length)
            {
                rulesPath = args[i + 1];
                i++;
            }
        }

        // Load initial rules if available
        if (File.Exists(rulesPath))
        {
            int loaded = ruleStore.LoadFile(rulesPath);
            Console.WriteLine($"[Rules] Loaded {loaded} rules from {rulesPath}");
        }
        else if (File.Exists("spec/test-data/rules.txt"))
        {
            int loaded = ruleStore.LoadFile("spec/test-data/rules.txt");
            Console.WriteLine($"[Rules] Loaded {loaded} rules from spec/test-data/rules.txt");
        }
        else
        {
            Console.WriteLine("[Rules] No initial rules file found. Starting with empty ruleset.");
        }

        // Start WinDivert packet filtering worker thread
        var packetLoop = new PacketLoop(ruleStore, ipcServer);
        var packetThread = new Thread(() => packetLoop.Run(cts.Token))
        {
            IsBackground = true,
            Name = "WinDivertWorker"
        };
        packetThread.Start();

        // Start periodic stats update broadcaster (every 2 seconds)
        var statsTask = Task.Run(async () =>
        {
            var lastStats = ipcServer.GetStats();
            while (!cts.Token.IsCancellationRequested)
            {
                await Task.Delay(2000, cts.Token);
                var current = ipcServer.GetStats();
                if (current.DnsQueries != lastStats.DnsQueries ||
                    current.TlsQueries != lastStats.TlsQueries ||
                    current.QuicDropped != lastStats.QuicDropped)
                {
                    ipcServer.BroadcastStatsUpdate();
                    lastStats = current;
                }
            }
        }, cts.Token);

        // Start Named Pipe server
        var ipcTask = Task.Run(() => ipcServer.StartAsync(cts.Token), cts.Token);

        Console.WriteLine("[Engine] Running and ready. Press Ctrl+C to shut down.");

        try
        {
            await Task.WhenAny(ipcTask, statsTask, Task.Delay(-1, cts.Token));
        }
        catch (TaskCanceledException) { }

        Console.WriteLine("[Engine] Engine successfully stopped.");
    }
}
