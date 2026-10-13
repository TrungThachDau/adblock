using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using AdblockApp.Services;
using AdblockApp.ViewModels;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace AdblockApp;

public partial class App : Application
{
  public static EngineClient Client { get; private set; } = null!;
  public static MainViewModel ViewModel { get; private set; } = null!;

  private MainWindow? _window;

  public App()
  {
    InitializeComponent();
    UnhandledException += (_, e) =>
    {
      e.Handled = true;
      LogCrash(e.Exception);
    };
    AppDomain.CurrentDomain.UnhandledException += (_, e) => LogCrash(e.ExceptionObject as Exception);
    System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
    {
      e.SetObserved();
      LogCrash(e.Exception);
    };
  }

  protected override void OnLaunched(LaunchActivatedEventArgs args)
  {
    Client = new EngineClient();
    var lists = new ListManagerService(Client);
    var allowlist = new AllowlistService(Client);
    ViewModel = new MainViewModel(Client, lists, allowlist, DispatcherQueue.GetForCurrentThread());

    _window = new MainWindow();
    _window.Activate();

    var startup = EnsureRustEngine();
    if (startup.ShouldConnect)
    {
      Client.Start();
    }
    if (startup.Message != null)
    {
      ViewModel.StatusText = startup.Message;
    }
  }

  private static (bool ShouldConnect, string? Message) EnsureRustEngine()
  {
    if (IsProcessRunning("adblock-engine-cs"))
    {
      return (false, "C# engine is still running. Stop it, then restart the app to start Rust.");
    }

    if (IsProcessRunning("adblock-engine-rs"))
    {
      return (true, null);
    }

    string enginePath = Path.Combine(AppContext.BaseDirectory, "adblock-engine-rs.exe");
    if (!File.Exists(enginePath))
    {
      return (false, "Rust engine executable is missing. Rebuild the app to bundle it.");
    }

    string rulesPath = Path.Combine(AppContext.BaseDirectory, "spec", "test-data", "rules.txt");
    try
    {
      Process.Start(new ProcessStartInfo
      {
        FileName = enginePath,
        Arguments = File.Exists(rulesPath) ? $"--rules \"{rulesPath}\"" : "",
        WorkingDirectory = AppContext.BaseDirectory,
        UseShellExecute = true,
        WindowStyle = ProcessWindowStyle.Hidden,
        Verb = "runas"
      });
      return (true, null);
    }
    catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
    {
      return (true, "Administrator permission was cancelled; the engine cannot block traffic.");
    }
    catch (Exception ex)
    {
      return (false, $"Could not start Rust engine: {ex.Message}");
    }
  }

  private static bool IsProcessRunning(string processName)
  {
    var processes = Process.GetProcessesByName(processName);
    bool running = processes.Length > 0;
    foreach (var process in processes)
    {
      process.Dispose();
    }
    return running;
  }

  private static void LogCrash(Exception? ex)
  {
    try
    {
      string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AdblockMonitor");
      Directory.CreateDirectory(dir);
      File.AppendAllText(Path.Combine(dir, "crash.log"), $"[{DateTime.Now:O}] {ex}\n\n");
    }
    catch { }
  }
}
