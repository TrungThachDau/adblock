using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AdblockApp.Services;

public class AllowlistService
{
    private readonly string _dataDir;
    private readonly string _configFile;
    private readonly EngineClient _engine;

    public List<string> Rules { get; } = new();

    public event Action? RulesChanged;

    public AllowlistService(EngineClient engine)
    {
        _engine = engine;
        _dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AdblockMonitor");
        _configFile = Path.Combine(_dataDir, "allowlist.json");

        Directory.CreateDirectory(_dataDir);
        LoadRules();
    }

    private void LoadRules()
    {
        Rules.Clear();
        if (File.Exists(_configFile))
        {
            try
            {
                string json = File.ReadAllText(_configFile);
                var list = JsonSerializer.Deserialize<List<string>>(json);
                if (list != null)
                {
                    Rules.AddRange(list);
                    return;
                }
            }
            catch { }
        }

        // Default initial allowlist entries
        Rules.Add("localhost");
        Rules.Add("@@||windowsupdate.microsoft.com^");
        SaveRules();
    }

    public void SaveRules()
    {
        try
        {
            Directory.CreateDirectory(_dataDir);
            string json = JsonSerializer.Serialize(Rules, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configFile, json);
        }
        catch { }
        RulesChanged?.Invoke();
    }

    public async Task<bool> AddRuleAsync(string rule)
    {
        rule = rule.Trim();
        if (string.IsNullOrEmpty(rule) || Rules.Contains(rule, StringComparer.OrdinalIgnoreCase))
            return false;

        Rules.Add(rule);
        SaveRules();

        if (_engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }

        return true;
    }

    public async Task<bool> RemoveRuleAsync(string rule)
    {
        bool removed = Rules.RemoveAll(r => r.Equals(rule, StringComparison.OrdinalIgnoreCase)) > 0;
        if (removed)
        {
            SaveRules();
            if (_engine.IsConnected)
            {
                await SyncWithEngineAsync();
            }
        }
        return removed;
    }

    public async Task ClearRulesAsync()
    {
        Rules.Clear();
        SaveRules();
        if (_engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }
    }

    public async Task SyncWithEngineAsync()
    {
        if (!_engine.IsConnected) return;
        try
        {
            await _engine.SetAllowlistAsync(Rules);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AllowlistService] Sync failed: {ex.Message}");
        }
    }
}
