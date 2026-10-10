using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AdblockApp.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;

namespace AdblockApp.ViewModels;

public class QueryLogItemViewModel
{
    public string Id { get; set; } = "";
    public string TimeFormatted { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string ClientIp { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Action { get; set; } = "";
    public string Reason { get; set; } = "";
    public bool IsBlocked => Action.Equals("blocked", StringComparison.OrdinalIgnoreCase) ||
                             Action.Equals("dropped", StringComparison.OrdinalIgnoreCase);
}

public partial class MainViewModel : ObservableObject
{
    private readonly EngineClient _client;
    private readonly DispatcherQueue _dispatcher;

    [ObservableProperty]
    private bool _isConnected;

    [ObservableProperty]
    private string _statusText = "Connecting to engine...";

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private int _activeRulesCount;

    [ObservableProperty]
    private long _dnsQueries;

    [ObservableProperty]
    private long _dnsBlocked;

    [ObservableProperty]
    private long _tlsQueries;

    [ObservableProperty]
    private long _tlsBlocked;

    [ObservableProperty]
    private long _quicDropped;

    [ObservableProperty]
    private long _totalBlocked;

    [ObservableProperty]
    private double _blockRatePercent;

    [ObservableProperty]
    private string _newRuleText = "";

    [ObservableProperty]
    private string _searchFilter = "";

    [ObservableProperty]
    private string _selectedRule = "";

    public ObservableCollection<QueryLogItemViewModel> QueryLogs { get; } = new();
    public ObservableCollection<string> RulesList { get; } = new();

    public MainViewModel(EngineClient client, DispatcherQueue dispatcher)
    {
        _client = client;
        _dispatcher = dispatcher;

        _client.ConnectionStateChanged += OnConnectionChanged;
        _client.QueryLogReceived += OnQueryLogReceived;
        _client.StatsUpdateReceived += OnStatsUpdateReceived;
    }

    private void OnConnectionChanged(bool connected)
    {
        _dispatcher.TryEnqueue(async () =>
        {
            IsConnected = connected;
            StatusText = connected ? "Engine Connected" : "Connecting to engine...";
            if (connected)
            {
                await RefreshStatusAsync();
                await RefreshRulesAsync();
            }
        });
    }

    private void OnQueryLogReceived(QueryLogModel log)
    {
        _dispatcher.TryEnqueue(() =>
        {
            var item = new QueryLogItemViewModel
            {
                Id = log.Id,
                TimeFormatted = DateTimeOffset.FromUnixTimeSeconds(log.Timestamp).ToLocalTime().ToString("HH:mm:ss"),
                Protocol = log.Protocol,
                ClientIp = log.ClientIp,
                Domain = log.Domain,
                Action = log.Action.ToUpperInvariant(),
                Reason = log.Reason
            };

            QueryLogs.Insert(0, item);
            if (QueryLogs.Count > 300)
            {
                QueryLogs.RemoveAt(QueryLogs.Count - 1);
            }
        });
    }

    private void OnStatsUpdateReceived(EngineStatsModel stats)
    {
        _dispatcher.TryEnqueue(() =>
        {
            UpdateStatsProperties(stats);
        });
    }

    private void UpdateStatsProperties(EngineStatsModel stats)
    {
        DnsQueries = stats.DnsQueries;
        DnsBlocked = stats.DnsBlocked;
        TlsQueries = stats.TlsQueries;
        TlsBlocked = stats.TlsBlocked;
        QuicDropped = stats.QuicDropped;

        TotalBlocked = stats.DnsBlocked + stats.TlsBlocked + stats.QuicDropped;
        long totalTraffic = stats.DnsQueries + stats.TlsQueries + stats.QuicDropped;
        BlockRatePercent = totalTraffic > 0 ? Math.Round((double)TotalBlocked / totalTraffic * 100.0, 1) : 0.0;
    }

    public async Task RefreshStatusAsync()
    {
        try
        {
            var status = await _client.GetStatusAsync();
            IsRunning = status.State == "running";
            ActiveRulesCount = status.ActiveRulesCount;
            UpdateStatsProperties(status.Stats);
        }
        catch { }
    }

    public async Task RefreshRulesAsync()
    {
        try
        {
            var result = await _client.ListRulesAsync(0, 500);
            ActiveRulesCount = result.Total;
            RulesList.Clear();
            foreach (var r in result.Rules)
            {
                RulesList.Add(r);
            }
        }
        catch { }
    }

    [RelayCommand]
    public async Task ToggleProtectionAsync()
    {
        if (!IsConnected) return;
        try
        {
            string target = IsRunning ? "paused" : "running";
            string newState = await _client.SetStateAsync(target);
            IsRunning = newState == "running";
        }
        catch { }
    }

    [RelayCommand]
    public async Task AddRuleAsync()
    {
        if (string.IsNullOrWhiteSpace(NewRuleText) || !IsConnected) return;
        try
        {
            string rule = NewRuleText.Trim();
            await _client.AddRulesAsync(new[] { rule });
            NewRuleText = "";
            await RefreshRulesAsync();
        }
        catch { }
    }

    [RelayCommand]
    public async Task RemoveSelectedRuleAsync()
    {
        if (string.IsNullOrWhiteSpace(SelectedRule) || !IsConnected) return;
        try
        {
            await _client.RemoveRulesAsync(new[] { SelectedRule });
            await RefreshRulesAsync();
        }
        catch { }
    }

    [RelayCommand]
    public async Task ClearAllRulesAsync()
    {
        if (!IsConnected) return;
        try
        {
            await _client.ClearRulesAsync();
            await RefreshRulesAsync();
        }
        catch { }
    }

    [RelayCommand]
    public async Task ImportRulesFromFileAsync(string filePath)
    {
        if (!File.Exists(filePath) || !IsConnected) return;
        try
        {
            var lines = File.ReadAllLines(filePath)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith("#"));
            await _client.AddRulesAsync(lines);
            await RefreshRulesAsync();
        }
        catch { }
    }

    [RelayCommand]
    public async Task ResetStatsAsync()
    {
        if (!IsConnected) return;
        try
        {
            await _client.ResetStatsAsync();
            var stats = await _client.GetStatsAsync();
            UpdateStatsProperties(stats);
        }
        catch { }
    }

    [RelayCommand]
    public void ClearLogs()
    {
        QueryLogs.Clear();
    }
}
