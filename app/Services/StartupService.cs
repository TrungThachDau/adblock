using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace AdblockApp.Services;

public static class StartupService
{
    private const string TaskName = "AdblockAutoStart";
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "AdblockApp";

    public static bool IsStartupEnabled()
    {
        try
        {
            if (IsScheduledTaskInstalled())
            {
                return true;
            }
        }
        catch { }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            var val = key?.GetValue(RunValueName) as string;
            return !string.IsNullOrWhiteSpace(val);
        }
        catch
        {
            return false;
        }
    }

    public static bool SetStartupEnabled(bool enable)
    {
        string exePath = Environment.ProcessPath
            ?? Path.Combine(AppContext.BaseDirectory, "AdblockApp.exe");
        string workDir = Path.GetDirectoryName(exePath) ?? AppContext.BaseDirectory;

        if (enable)
        {
            if (CreateScheduledTask(exePath, workDir))
            {
                RemoveRegistryRunValue();
                return true;
            }

            // Fallback to HKCU Run registry key if Task Scheduler is unavailable
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
                key?.SetValue(RunValueName, $"\"{exePath}\"");
                return true;
            }
            catch
            {
                return false;
            }
        }
        else
        {
            DeleteScheduledTask();
            RemoveRegistryRunValue();
            return !IsStartupEnabled();
        }
    }

    private static bool IsScheduledTaskInstalled()
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            Arguments = $"/Query /TN \"{TaskName}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        });
        if (proc == null) return false;
        proc.WaitForExit(3000);
        return proc.ExitCode == 0;
    }

    private static bool CreateScheduledTask(string exePath, string workDir)
    {
        string tempXml = Path.Combine(Path.GetTempPath(), $"adblock_task_{Guid.NewGuid():N}.xml");
        try
        {
            string currentUser = WindowsIdentity.GetCurrent().Name;
            string escapedUser = SecurityElement.Escape(currentUser) ?? currentUser;
            string escapedExe = SecurityElement.Escape(exePath) ?? exePath;
            string escapedDir = SecurityElement.Escape(workDir.TrimEnd('\\')) ?? workDir;

            string xml = $"""
                <?xml version="1.0" encoding="UTF-16"?>
                <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                  <RegistrationInfo>
                    <Description>Auto-start Adblock with Administrator privileges at Windows logon.</Description>
                  </RegistrationInfo>
                  <Triggers>
                    <LogonTrigger>
                      <Enabled>true</Enabled>
                      <UserId>{escapedUser}</UserId>
                    </LogonTrigger>
                  </Triggers>
                  <Principals>
                    <Principal id="Author">
                      <UserId>{escapedUser}</UserId>
                      <LogonType>InteractiveToken</LogonType>
                      <RunLevel>HighestAvailable</RunLevel>
                    </Principal>
                  </Principals>
                  <Settings>
                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                    <AllowHardTerminate>true</AllowHardTerminate>
                    <StartWhenAvailable>true</StartWhenAvailable>
                    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                    <IdleSettings>
                      <StopOnIdleEnd>false</StopOnIdleEnd>
                      <RestartOnIdle>false</RestartOnIdle>
                    </IdleSettings>
                    <AllowStartOnDemand>true</AllowStartOnDemand>
                    <Enabled>true</Enabled>
                    <Hidden>false</Hidden>
                    <RunOnlyIfIdle>false</RunOnlyIfIdle>
                    <WakeToRun>false</WakeToRun>
                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                    <Priority>7</Priority>
                  </Settings>
                  <Actions Context="Author">
                    <Exec>
                      <Command>{escapedExe}</Command>
                      <WorkingDirectory>{escapedDir}</WorkingDirectory>
                    </Exec>
                  </Actions>
                </Task>
                """;

            File.WriteAllText(tempXml, xml, Encoding.Unicode);

            // A RunLevel=HighestAvailable task can only be registered from an elevated process.
            // When running unelevated (e.g. debugging from a non-admin Visual Studio), prompt via UAC.
            return RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{tempXml}\" /F") == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            try { if (File.Exists(tempXml)) File.Delete(tempXml); } catch { }
        }
    }

    private static void DeleteScheduledTask()
    {
        try
        {
            if (IsScheduledTaskInstalled())
            {
                RunSchtasks($"/Delete /TN \"{TaskName}\" /F");
            }
        }
        catch { }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Runs schtasks.exe, elevating through UAC when the current process is not admin. Returns exit code or -1.</summary>
    private static int RunSchtasks(string arguments)
    {
        try
        {
            bool elevated = IsElevated();
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            if (elevated)
            {
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
            }
            else
            {
                psi.UseShellExecute = true;
                psi.Verb = "runas";
            }

            using var proc = Process.Start(psi);
            if (proc == null) return -1;
            if (!proc.WaitForExit(30000)) return -1;
            return proc.ExitCode;
        }
        catch
        {
            return -1; // includes UAC cancelled
        }
    }

    private static void RemoveRegistryRunValue()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            key?.DeleteValue(RunValueName, throwOnMissingValue: false);
        }
        catch { }
    }
}

