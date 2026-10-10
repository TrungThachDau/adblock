using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AdblockApp.Services;

public class BlocklistSubscription
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public bool IsEnabled { get; set; } = true;
    public string LocalPath { get; set; } = "";
    public int RuleCount { get; set; }
    public DateTime? LastUpdated { get; set; }
    public string Status { get; set; } = "Ready";
}

public class ListManagerService
{
    private readonly string _dataDir;
    private readonly string _cacheDir;
    private readonly string _configFile;
    private readonly HttpClient _http;
    private readonly EngineClient _engine;

    public List<BlocklistSubscription> Subscriptions { get; } = new();

    public event Action? SubscriptionsChanged;

    public ListManagerService(EngineClient engine)
    {
        _engine = engine;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("AdblockApp/1.0 (Windows NT 10.0; Win64; x64)");

        _dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AdblockMonitor");
        _cacheDir = Path.Combine(_dataDir, "lists");
        _configFile = Path.Combine(_dataDir, "subscriptions.json");

        Directory.CreateDirectory(_cacheDir);
        LoadSubscriptions();
    }

    private void LoadSubscriptions()
    {
        Subscriptions.Clear();

        if (File.Exists(_configFile))
        {
            try
            {
                string json = File.ReadAllText(_configFile);
                var list = JsonSerializer.Deserialize<List<BlocklistSubscription>>(json);
                if (list != null && list.Count > 0)
                {
                    Subscriptions.AddRange(list);
                    return;
                }
            }
            catch { }
        }

        // Seed default initial lists
        SeedDefaultLists();
        SaveSubscriptions();
    }

    private void SeedDefaultLists()
    {
        // 1. Check if workspace sample list exists
        string sampleList = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "spec", "testdata", "sample_list.txt");
        if (File.Exists(sampleList))
        {
            Subscriptions.Add(new BlocklistSubscription
            {
                Id = "sample-list",
                Name = "Spec Sample Blocklist (Local)",
                Url = Path.GetFullPath(sampleList),
                IsEnabled = true,
                LocalPath = Path.GetFullPath(sampleList),
                RuleCount = CountRulesInFile(sampleList),
                LastUpdated = DateTime.Now,
                Status = "Active (Local)"
            });
        }

        // 2. Curated standard DNS filters
        Subscriptions.Add(new BlocklistSubscription
        {
            Id = "adguard-dns",
            Name = "AdGuard DNS Filter",
            Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
            IsEnabled = true,
            LocalPath = Path.Combine(_cacheDir, "adguard-dns.txt"),
            Status = "Not downloaded yet"
        });

        Subscriptions.Add(new BlocklistSubscription
        {
            Id = "peter-lowe",
            Name = "Peter Lowe's Ad & Tracker List",
            Url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
            IsEnabled = true,
            LocalPath = Path.Combine(_cacheDir, "peter-lowe.txt"),
            Status = "Not downloaded yet"
        });
    }

    public void SaveSubscriptions()
    {
        try
        {
            Directory.CreateDirectory(_dataDir);
            string json = JsonSerializer.Serialize(Subscriptions, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configFile, json);
        }
        catch { }
        SubscriptionsChanged?.Invoke();
    }

    public IReadOnlyList<string> GetEnabledListPaths()
    {
        var paths = new List<string>();
        foreach (var sub in Subscriptions)
        {
            if (sub.IsEnabled && File.Exists(sub.LocalPath))
            {
                paths.Add(sub.LocalPath);
            }
        }
        return paths;
    }

    public async Task<bool> AddListAsync(string name, string url)
    {
        url = url.Trim();
        if (string.IsNullOrEmpty(url)) return false;

        string id = Guid.NewGuid().ToString("N");
        string localPath = Path.Combine(_cacheDir, $"{id}.txt");

        var sub = new BlocklistSubscription
        {
            Id = id,
            Name = string.IsNullOrWhiteSpace(name) ? GetDomainFromUrl(url) : name.Trim(),
            Url = url,
            IsEnabled = true,
            LocalPath = localPath,
            Status = "Downloading..."
        };

        Subscriptions.Add(sub);
        SaveSubscriptions();

        bool downloaded = await DownloadListContentAsync(sub);
        SaveSubscriptions();

        if (downloaded && _engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }

        return downloaded;
    }

    public async Task<bool> UpdateListAsync(string id)
    {
        var sub = Subscriptions.FirstOrDefault(s => s.Id == id);
        if (sub == null) return false;

        bool ok = await DownloadListContentAsync(sub);
        SaveSubscriptions();

        if (ok && sub.IsEnabled && _engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }

        return ok;
    }

    public async Task UpdateAllListsAsync()
    {
        var tasks = Subscriptions.Where(s => s.IsEnabled && !s.Url.StartsWith("file:", StringComparison.OrdinalIgnoreCase) && File.Exists(s.LocalPath) || !File.Exists(s.LocalPath))
            .Select(s => DownloadListContentAsync(s))
            .ToList();

        await Task.WhenAll(tasks);
        SaveSubscriptions();

        if (_engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }
    }

    public async Task ToggleListAsync(string id, bool isEnabled)
    {
        var sub = Subscriptions.FirstOrDefault(s => s.Id == id);
        if (sub == null) return;

        sub.IsEnabled = isEnabled;
        SaveSubscriptions();

        // If toggled on and not downloaded, download it
        if (isEnabled && !File.Exists(sub.LocalPath) && sub.Url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            await DownloadListContentAsync(sub);
            SaveSubscriptions();
        }

        if (_engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }
    }

    public async Task DeleteListAsync(string id)
    {
        var sub = Subscriptions.FirstOrDefault(s => s.Id == id);
        if (sub == null) return;

        Subscriptions.Remove(sub);
        try
        {
            if (File.Exists(sub.LocalPath) && !sub.LocalPath.Contains("spec"))
            {
                File.Delete(sub.LocalPath);
            }
        }
        catch { }

        SaveSubscriptions();

        if (_engine.IsConnected)
        {
            await SyncWithEngineAsync();
        }
    }

    public async Task SyncWithEngineAsync()
    {
        if (!_engine.IsConnected) return;

        var enabledPaths = GetEnabledListPaths();
        try
        {
            await _engine.SetListsAsync(enabledPaths);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ListManager] SyncWithEngine failed: {ex.Message}");
        }
    }

    private async Task<bool> DownloadListContentAsync(BlocklistSubscription sub)
    {
        // Handle local files
        if (File.Exists(sub.Url))
        {
            sub.LocalPath = sub.Url;
            sub.RuleCount = CountRulesInFile(sub.Url);
            sub.LastUpdated = DateTime.Now;
            sub.Status = $"Ready ({sub.RuleCount:N0} rules)";
            return true;
        }

        if (!sub.Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !sub.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            sub.Status = "Invalid URL";
            return false;
        }

        try
        {
            sub.Status = "Downloading...";
            SubscriptionsChanged?.Invoke();

            using var resp = await _http.GetAsync(sub.Url, HttpCompletionOption.ResponseHeadersRead);
            if (!resp.IsSuccessStatusCode)
            {
                sub.Status = $"Error {(int)resp.StatusCode}: {resp.ReasonPhrase}";
                return false;
            }

            string tempFile = sub.LocalPath + ".tmp";
            using (var stream = await resp.Content.ReadAsStreamAsync())
            using (var fs = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await stream.CopyToAsync(fs);
            }

            if (File.Exists(sub.LocalPath))
            {
                File.Delete(sub.LocalPath);
            }
            File.Move(tempFile, sub.LocalPath);

            sub.RuleCount = CountRulesInFile(sub.LocalPath);
            sub.LastUpdated = DateTime.Now;
            sub.Status = $"Updated ({sub.RuleCount:N0} rules)";
            return true;
        }
        catch (Exception ex)
        {
            sub.Status = $"Download failed: {ex.Message}";
            return false;
        }
    }

    private static int CountRulesInFile(string path)
    {
        if (!File.Exists(path)) return 0;
        int count = 0;
        try
        {
            using var reader = new StreamReader(path);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#") || trimmed.StartsWith("!"))
                    continue;
                count++;
            }
        }
        catch { }
        return count;
    }

    private static string GetDomainFromUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.Host;
        }
        catch
        {
            return url;
        }
    }
}

