using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using AdblockApp.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;

namespace AdblockApp.ViewModels;

public class BulkObservableCollection<T> : ObservableCollection<T>
{
    private bool _suppressNotification;

    public void AddRangeToStart(IReadOnlyList<T> items, int maxCount = 300)
    {
        if (items.Count == 0) return;

        _suppressNotification = true;
        try
        {
            for (int i = items.Count - 1; i >= 0; i--)
            {
                Items.Insert(0, items[i]);
            }
            while (Items.Count > maxCount)
            {
                Items.RemoveAt(Items.Count - 1);
            }
        }
        finally
        {
            _suppressNotification = false;
            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }

    protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
    {
        if (!_suppressNotification)
        {
            base.OnCollectionChanged(e);
        }
    }
}

public class QueryLogItemViewModel
{
    public string Id { get; set; } = "";
    public string TimeFormatted { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string ClientIp { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Action { get; set; } = "";
    public string Reason { get; set; } = "";
    public bool IsBlocked => Action.Equals("BLOCKED", StringComparison.OrdinalIgnoreCase) ||
                             Action.Equals("DROPPED", StringComparison.OrdinalIgnoreCase);

    public override string ToString() => $"[{TimeFormatted}] [{Protocol,-4}] {Action,-8} {Domain} {(string.IsNullOrEmpty(Reason) ? "" : $"({Reason})")}";
}

public class BlockedQueryItemViewModel
{
    public string Id { get; set; } = "";
    public string TimeFormatted { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string ClientIp { get; set; } = "";
    public string Domain { get; set; } = "";
    public string MatchedRule { get; set; } = "";
    public string SourceList { get; set; } = "";
}

public partial class MainViewModel : ObservableObject
{
    private readonly EngineClient _client;
    private readonly ListManagerService _listManager;
    private readonly AllowlistService _allowlist;
    private readonly DispatcherQueue _dispatcher;

    private readonly ConcurrentQueue<BlockedQueryItemViewModel> _incomingBlocked = new();
    private readonly ConcurrentQueue<QueryLogItemViewModel> _incomingLogs = new();
    private volatile EngineStatsModel? _latestStats;
    private readonly DispatcherQueueTimer _batchTimer;

    public ListManagerService ListManager => _listManager;
    public AllowlistService Allowlist => _allowlist;

    [ObservableProperty]
    private bool _isConnected;

    [ObservableProperty]
    private string _statusText = "Connecting to engine...";

    [ObservableProperty]
    private string _engineName = "Detecting...";

    [ObservableProperty]
    private string _engineVersion = "";

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private int _activeRulesCount;

    [ObservableProperty]
    private int _allowlistCount;

    [ObservableProperty]
    private int _listsCount;

    [ObservableProperty]
    private long _uptimeSeconds;

    [ObservableProperty]
    private string _uptimeFormatted = "0s";

    [ObservableProperty]
    private long _allowedCount;

    [ObservableProperty]
    private long _blockedCount;

    public long TotalBlocked => BlockedCount;

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
    private double _ramMb;

    [ObservableProperty]
    private double _blockRatePercent;

    [ObservableProperty]
    private string _newSubscriptionUrl = "";

    [ObservableProperty]
    private string _newSubscriptionName = "";

    [ObservableProperty]
    private string _newAllowlistRule = "";

    public ObservableCollection<BlocklistSubscription> Subscriptions { get; } = new();
    public ObservableCollection<string> AllowlistRules { get; } = new();
    public ObservableCollection<BlockedQueryItemViewModel> RecentBlocked { get; } = new();
    public BulkObservableCollection<QueryLogItemViewModel> QueryLogs { get; } = new();

    public MainViewModel(EngineClient client, ListManagerService listManager, AllowlistService allowlist, DispatcherQueue dispatcher)
    {
        _client = client;
        _listManager = listManager;
        _allowlist = allowlist;
        _dispatcher = dispatcher;

        _batchTimer = _dispatcher.CreateTimer();
        _batchTimer.Interval = TimeSpan.FromMilliseconds(250);
        _batchTimer.Tick += OnBatchTimerTick;
        _batchTimer.Start();

        _client.ConnectionStateChanged += OnConnectionChanged;
        _client.BlockedQueryReceived += OnBlockedQueryReceived;
        _client.QueryLogReceived += OnQueryLogReceived;
        _client.StatsUpdateReceived += OnStatsUpdateReceived;

        _listManager.SubscriptionsChanged += RefreshSubscriptionsCollection;
        _allowlist.RulesChanged += RefreshAllowlistCollection;

        RefreshSubscriptionsCollection();
        RefreshAllowlistCollection();
    }

    private void RefreshSubscriptionsCollection()
    {
        _dispatcher.TryEnqueue(() =>
        {
            Subscriptions.Clear();
            foreach (var s in _listManager.Subscriptions)
            {
                Subscriptions.Add(s);
            }
        });
    }

    private void RefreshAllowlistCollection()
    {
        _dispatcher.TryEnqueue(() =>
        {
            AllowlistRules.Clear();
            foreach (var r in _allowlist.Rules)
            {
                AllowlistRules.Add(r);
            }
            AllowlistCount = AllowlistRules.Count;
        });
    }

    private void OnConnectionChanged(bool connected)
    {
        _dispatcher.TryEnqueue(() =>
        {
            IsConnected = connected;
            if (connected)
            {
                StatusText = $"Connected to engine (pipe: \\\\.\\pipe\\{_client.ActivePipeName})";
            }
            else
            {
                StatusText = "Engine disconnected. Reconnecting via Named Pipe...";
                EngineName = "Disconnected";
                EngineVersion = "";
            }
        });

        if (connected)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await RefreshStatusAsync();
                    await _listManager.SyncWithEngineAsync();
                    await _allowlist.SyncWithEngineAsync();
                    await FetchRecentBlockedAsync();
                    await RefreshStatusAsync();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[MainViewModel] Connection sync failed: {ex.Message}");
                }
            });
        }
    }

    private void OnBlockedQueryReceived(BlockedQueryModel b)
    {
        var item = new BlockedQueryItemViewModel
        {
            Id = b.Id,
            TimeFormatted = DateTimeOffset.FromUnixTimeSeconds(b.Timestamp).ToLocalTime().ToString("HH:mm:ss"),
            Protocol = b.Protocol,
            ClientIp = b.ClientIp,
            Domain = b.Domain,
            MatchedRule = b.MatchedRule,
            SourceList = b.SourceList
        };

        _incomingBlocked.Enqueue(item);
        while (_incomingBlocked.Count > 100)
        {
            _incomingBlocked.TryDequeue(out _);
        }
    }

    private void OnQueryLogReceived(QueryLogModel log)
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

        _incomingLogs.Enqueue(item);
        while (_incomingLogs.Count > 300)
        {
            _incomingLogs.TryDequeue(out _);
        }
    }

    private void OnStatsUpdateReceived(EngineStatsModel stats)
    {
        _latestStats = stats;
    }

    private void OnBatchTimerTick(DispatcherQueueTimer sender, object args)
    {
        // 1. Process latest engine stats
        var stats = _latestStats;
        if (stats != null)
        {
            _latestStats = null;
            UpdateStatsProperties(stats);
        }

        // 2. Process incoming blocked queries
        var blockedList = new List<BlockedQueryItemViewModel>();
        while (_incomingBlocked.TryDequeue(out var b) && blockedList.Count < 50)
        {
            blockedList.Add(b);
        }
        if (blockedList.Count > 0)
        {
            for (int i = blockedList.Count - 1; i >= 0; i--)
            {
                RecentBlocked.Insert(0, blockedList[i]);
            }
            while (RecentBlocked.Count > 100)
            {
                RecentBlocked.RemoveAt(RecentBlocked.Count - 1);
            }
        }

        // 3. Process incoming query logs in bulk
        var logsList = new List<QueryLogItemViewModel>();
        while (_incomingLogs.TryDequeue(out var log) && logsList.Count < 100)
        {
            logsList.Add(log);
        }
        if (logsList.Count > 0)
        {
            QueryLogs.AddRangeToStart(logsList, 300);
        }
    }

    private void UpdateStatsProperties(EngineStatsModel stats)
    {
        AllowedCount = stats.AllowedCount;
        BlockedCount = stats.BlockedCount;
        DnsQueries = stats.DnsQueries;
        DnsBlocked = stats.DnsBlocked;
        TlsQueries = stats.TlsQueries;
        TlsBlocked = stats.TlsBlocked;
        QuicDropped = stats.QuicDropped;
        RamMb = stats.RamMb;
        UptimeSeconds = stats.UptimeSeconds;

        var ts = TimeSpan.FromSeconds(stats.UptimeSeconds);
        UptimeFormatted = ts.TotalHours >= 1 ? $"{(int)ts.TotalHours}h {ts.Minutes}m {ts.Seconds}s" : $"{ts.Minutes}m {ts.Seconds}s";

        long total = stats.AllowedCount + stats.BlockedCount;
        BlockRatePercent = total > 0 ? Math.Round((double)stats.BlockedCount / total * 100.0, 1) : 0.0;
    }

    public async Task RefreshStatusAsync()
    {
        if (!_client.IsConnected) return;

        try
        {
            var status = await _client.GetStatusAsync();
            var stats = status.Stats ?? await _client.GetStatsAsync();

            _dispatcher.TryEnqueue(() =>
            {
                EngineName = status.Name;
                EngineVersion = status.Version;
                IsRunning = status.State.Equals("running", StringComparison.OrdinalIgnoreCase);
                ActiveRulesCount = status.ActiveRulesCount;
                AllowlistCount = status.AllowlistCount;
                ListsCount = status.ListsCount;
                UptimeSeconds = status.UptimeSeconds;

                var ts = TimeSpan.FromSeconds(status.UptimeSeconds);
                UptimeFormatted = ts.TotalHours >= 1 ? $"{(int)ts.TotalHours}h {ts.Minutes}m {ts.Seconds}s" : $"{ts.Minutes}m {ts.Seconds}s";
                StatusText = $"Connected: {status.Name} v{status.Version} ({status.State})";

                UpdateStatsProperties(stats);
            });
        }
        catch { }
    }

    public async Task FetchRecentBlockedAsync()
    {
        if (!_client.IsConnected) return;
        try
        {
            var items = await _client.GetRecentBlockedAsync(50);
            _dispatcher.TryEnqueue(() =>
            {
                RecentBlocked.Clear();
                foreach (var b in items)
                {
                    RecentBlocked.Add(new BlockedQueryItemViewModel
                    {
                        Id = b.Id,
                        TimeFormatted = DateTimeOffset.FromUnixTimeSeconds(b.Timestamp).ToLocalTime().ToString("HH:mm:ss"),
                        Protocol = b.Protocol,
                        ClientIp = b.ClientIp,
                        Domain = b.Domain,
                        MatchedRule = b.MatchedRule,
                        SourceList = b.SourceList
                    });
                }
            });
        }
        catch { }
    }

    [RelayCommand]
    public async Task ToggleProtectionAsync()
    {
        if (!_client.IsConnected) return;
        try
        {
            if (IsRunning)
            {
                string state = await _client.StopEngineAsync();
                IsRunning = state.Equals("running", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                string state = await _client.StartEngineAsync();
                IsRunning = state.Equals("running", StringComparison.OrdinalIgnoreCase);
            }
            StatusText = $"Connected: {EngineName} ({ (IsRunning ? "running" : "stopped") })";
        }
        catch { }
    }

    [RelayCommand]
    public async Task ResetStatsAsync()
    {
        if (!_client.IsConnected) return;
        try
        {
            await _client.ResetStatsAsync();
            var stats = await _client.GetStatsAsync();
            _dispatcher.TryEnqueue(() => UpdateStatsProperties(stats));
        }
        catch { }
    }

    [RelayCommand]
    public async Task AddSubscriptionAsync()
    {
        string url = NewSubscriptionUrl.Trim();
        string name = NewSubscriptionName.Trim();
        if (string.IsNullOrEmpty(url)) return;

        NewSubscriptionUrl = "";
        NewSubscriptionName = "";

        await _listManager.AddListAsync(name, url);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task ToggleSubscriptionAsync(string id)
    {
        var sub = Subscriptions.FirstOrDefault(s => s.Id == id);
        if (sub == null) return;

        await _listManager.ToggleListAsync(id, !sub.IsEnabled);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task UpdateSubscriptionAsync(string id)
    {
        await _listManager.UpdateListAsync(id);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task UpdateAllSubscriptionsAsync()
    {
        await _listManager.UpdateAllListsAsync();
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task DeleteSubscriptionAsync(string id)
    {
        await _listManager.DeleteListAsync(id);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task AddAllowlistRuleAsync()
    {
        string rule = NewAllowlistRule.Trim();
        if (string.IsNullOrEmpty(rule)) return;

        NewAllowlistRule = "";
        await _allowlist.AddRuleAsync(rule);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task RemoveAllowlistRuleAsync(string rule)
    {
        await _allowlist.RemoveRuleAsync(rule);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task ClearAllowlistAsync()
    {
        await _allowlist.ClearRulesAsync();
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public async Task AllowBlockedDomainAsync(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        await _allowlist.AddRuleAsync(domain);
        await RefreshStatusAsync();
    }

    [RelayCommand]
    public void ClearRecentBlocked()
    {
        RecentBlocked.Clear();
    }

    [RelayCommand]
    public void ClearLogs()
    {
        QueryLogs.Clear();
    }
}
