using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace AdblockApp.Services;

public class PrivateDnsConfigData
{
    public bool Enabled { get; set; }
    public string Url { get; set; } = "";
}

public class PrivateDnsService
{
    private readonly string _dataDir;
    private readonly string _configFile;
    private readonly EngineClient _engine;

    public bool Enabled { get; private set; }
    public string Url { get; private set; } = "";

    public event Action? ConfigChanged;

    public PrivateDnsService(EngineClient engine)
    {
        _engine = engine;
        _dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AdblockMonitor"
        );
        _configFile = Path.Combine(_dataDir, "private_dns.json");

        Directory.CreateDirectory(_dataDir);
        LoadConfig();
    }

    private void LoadConfig()
    {
        if (File.Exists(_configFile))
        {
            try
            {
                string json = File.ReadAllText(_configFile);
                var data = JsonSerializer.Deserialize<PrivateDnsConfigData>(json);
                if (data != null)
                {
                    Enabled = data.Enabled;
                    Url = data.Url ?? "";
                    return;
                }
            }
            catch { }
        }

        Enabled = false;
        Url = "";
    }

    public void SaveConfig()
    {
        try
        {
            Directory.CreateDirectory(_dataDir);
            var data = new PrivateDnsConfigData
            {
                Enabled = Enabled,
                Url = Url
            };
            string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configFile, json);
        }
        catch { }
        ConfigChanged?.Invoke();
    }

    public async Task<PrivateDnsConfigModel> UpdateConfigAsync(bool enabled, string url)
    {
        url = (url ?? "").Trim();
        if (enabled && string.IsNullOrEmpty(url))
        {
            throw new ArgumentException("Please enter a custom DoH URL (e.g. https://cloudflare-dns.com/dns-query).");
        }

        if (_engine.IsConnected)
        {
            var result = await _engine.SetPrivateDnsAsync(enabled, url);
            Enabled = result.Enabled;
            Url = result.Url;
            SaveConfig();
            return result;
        }

        Enabled = enabled;
        Url = url;
        SaveConfig();
        return new PrivateDnsConfigModel(Enabled, Url);
    }

    public async Task SyncWithEngineAsync()
    {
        if (!_engine.IsConnected) return;
        try
        {
            var res = await _engine.SetPrivateDnsAsync(Enabled, Url);
            Enabled = res.Enabled;
            Url = res.Url;
            ConfigChanged?.Invoke();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[PrivateDnsService] Sync failed: {ex.Message}");
        }
    }
}
