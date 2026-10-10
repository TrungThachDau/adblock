using System;
using System.IO;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using WinRT;

namespace AdblockApp;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            try
            {
                File.WriteAllText(@"d:\adblock\crash_unhandled.txt", e.ExceptionObject?.ToString() ?? "Unknown crash");
            }
            catch { }
        };

        try
        {
            ComWrappersSupport.InitializeComWrappers();
            Application.Start((p) =>
            {
                try
                {
                    var context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
                    System.Threading.SynchronizationContext.SetSynchronizationContext(context);
                    _ = new App();
                }
                catch (Exception ex)
                {
                    File.WriteAllText(@"d:\adblock\crash_app_start.txt", ex.ToString());
                }
            });
        }
        catch (Exception ex)
        {
            File.WriteAllText(@"d:\adblock\crash_main.txt", ex.ToString());
        }
    }
}
