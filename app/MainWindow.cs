using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AdblockApp.Services;
using AdblockApp.ViewModels;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace AdblockApp;

public class MainWindow : Window
{
    public MainViewModel ViewModel { get; }
    private readonly EngineClient _client;

    // UI Controls
    private readonly TextBlock _statusSubtitle;
    private readonly ToggleSwitch _protectionToggle;
    private readonly TextBlock _totalBlockedText;
    private readonly TextBlock _blockRateText;
    private readonly TextBlock _dnsBlockedText;
    private readonly TextBlock _dnsTotalText;
    private readonly TextBlock _tlsBlockedText;
    private readonly TextBlock _tlsTotalText;
    private readonly TextBlock _quicDroppedText;
    private readonly TextBlock _rulesCountHeader;
    private readonly TextBlock _diagnosticsOutput;

    private readonly ListView _queryLogListView;
    private readonly ListView _rulesListView;
    private readonly TextBox _newRuleInput;

    public MainWindow()
    {
        this.Title = "Adblock Monitor (WinDivert 2.x)";

        _client = new EngineClient();
        ViewModel = new MainViewModel(_client, this.DispatcherQueue);

        // Header controls
        _statusSubtitle = new TextBlock
        {
            Text = "Connecting to engine...",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        };

        _protectionToggle = new ToggleSwitch
        {
            OnContent = "Protection Active",
            OffContent = "Protection Paused",
            IsEnabled = false,
            VerticalAlignment = VerticalAlignment.Center
        };
        _protectionToggle.Toggled += async (s, e) =>
        {
            if (_protectionToggle.IsOn != ViewModel.IsRunning)
            {
                await ViewModel.ToggleProtectionAsync();
            }
        };

        // Metric Card Controls
        _totalBlockedText = new TextBlock
        {
            Text = "0",
            FontSize = 32,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 224, 64, 251))
        };
        _blockRateText = new TextBlock
        {
            Text = "0.0% Block Rate",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        };

        _dnsBlockedText = new TextBlock
        {
            Text = "0",
            FontSize = 32,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 0, 230, 118))
        };
        _dnsTotalText = new TextBlock
        {
            Text = "Total: 0 queries",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        };

        _tlsBlockedText = new TextBlock
        {
            Text = "0",
            FontSize = 32,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 0, 229, 255))
        };
        _tlsTotalText = new TextBlock
        {
            Text = "Total: 0 handshakes",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        };

        _quicDroppedText = new TextBlock
        {
            Text = "0",
            FontSize = 32,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 255, 145, 0))
        };

        _rulesCountHeader = new TextBlock
        {
            Text = "0 Active Rules",
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        };

        _diagnosticsOutput = new TextBlock
        {
            Text = "Ready. Connected via Named Pipe (\\\\.\\pipe\\adblock-engine).",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(220, 200, 200, 200))
        };

        _newRuleInput = new TextBox
        {
            PlaceholderText = "e.g. adservice.google.com, *.doubleclick.net",
            MinWidth = 340
        };
        _newRuleInput.KeyDown += async (s, e) =>
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                await AddRuleFromInputAsync();
            }
        };

        _queryLogListView = new ListView
        {
            ItemsSource = ViewModel.QueryLogs,
            SelectionMode = ListViewSelectionMode.None
        };

        _rulesListView = new ListView
        {
            ItemsSource = ViewModel.RulesList,
            SelectionMode = ListViewSelectionMode.Single
        };

        this.Content = BuildRootLayout();

        // Bind ViewModel changes to UI updates
        ViewModel.PropertyChanged += (s, e) =>
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                switch (e.PropertyName)
                {
                    case nameof(ViewModel.IsConnected):
                        _protectionToggle.IsEnabled = ViewModel.IsConnected;
                        break;
                    case nameof(ViewModel.StatusText):
                        _statusSubtitle.Text = ViewModel.StatusText;
                        break;
                    case nameof(ViewModel.IsRunning):
                        if (_protectionToggle.IsOn != ViewModel.IsRunning)
                            _protectionToggle.IsOn = ViewModel.IsRunning;
                        break;
                    case nameof(ViewModel.TotalBlocked):
                        _totalBlockedText.Text = ViewModel.TotalBlocked.ToString("N0");
                        break;
                    case nameof(ViewModel.BlockRatePercent):
                        _blockRateText.Text = $"{ViewModel.BlockRatePercent:F1}% Block Rate";
                        break;
                    case nameof(ViewModel.DnsBlocked):
                        _dnsBlockedText.Text = ViewModel.DnsBlocked.ToString("N0");
                        break;
                    case nameof(ViewModel.DnsQueries):
                        _dnsTotalText.Text = $"Total: {ViewModel.DnsQueries:N0} queries";
                        break;
                    case nameof(ViewModel.TlsBlocked):
                        _tlsBlockedText.Text = ViewModel.TlsBlocked.ToString("N0");
                        break;
                    case nameof(ViewModel.TlsQueries):
                        _tlsTotalText.Text = $"Total: {ViewModel.TlsQueries:N0} handshakes";
                        break;
                    case nameof(ViewModel.QuicDropped):
                        _quicDroppedText.Text = ViewModel.QuicDropped.ToString("N0");
                        break;
                    case nameof(ViewModel.ActiveRulesCount):
                        _rulesCountHeader.Text = $"{ViewModel.ActiveRulesCount:N0} Active Rules";
                        break;
                }
            });
        };

        _client.Start();
    }

    private UIElement BuildRootLayout()
    {
        var rootGrid = new Grid
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 24, 24, 27))
        };
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        // Header Bar
        var headerBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 32, 32, 36)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 48, 48, 54)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(24, 16, 24, 16)
        };
        Grid.SetRow(headerBorder, 0);

        var headerGrid = new Grid();
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var titleStack = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 16,
            VerticalAlignment = VerticalAlignment.Center
        };
        titleStack.Children.Add(new TextBlock { Text = "🛡️", FontSize = 28, VerticalAlignment = VerticalAlignment.Center });

        var textStack = new StackPanel { Spacing = 2 };
        textStack.Children.Add(new TextBlock
        {
            Text = "Adblock Engine Monitor",
            FontSize = 20,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Colors.White)
        });
        textStack.Children.Add(_statusSubtitle);
        titleStack.Children.Add(textStack);

        Grid.SetColumn(titleStack, 0);
        Grid.SetColumn(_protectionToggle, 1);
        headerGrid.Children.Add(titleStack);
        headerGrid.Children.Add(_protectionToggle);
        headerBorder.Child = headerGrid;
        rootGrid.Children.Add(headerBorder);

        // Tab Navigation
        var tabView = new TabView
        {
            IsAddTabButtonVisible = false,
            Padding = new Thickness(16, 8, 16, 16)
        };
        Grid.SetRow(tabView, 1);

        // Tab 1: Dashboard
        var dashTab = new TabViewItem { Header = "Dashboard", IsClosable = false };
        dashTab.Content = BuildDashboardContent();
        tabView.TabItems.Add(dashTab);

        // Tab 2: Live Query Log
        var logTab = new TabViewItem { Header = "Live Query Log", IsClosable = false };
        logTab.Content = BuildQueryLogContent();
        tabView.TabItems.Add(logTab);

        // Tab 3: Domain Rules
        var rulesTab = new TabViewItem { Header = "Domain Rules", IsClosable = false };
        rulesTab.Content = BuildRulesContent();
        tabView.TabItems.Add(rulesTab);

        rootGrid.Children.Add(tabView);
        return rootGrid;
    }

    private UIElement BuildDashboardContent()
    {
        var scroll = new ScrollViewer { Padding = new Thickness(16) };
        var stack = new StackPanel { Spacing = 20 };

        // 4 Metric Cards
        var cardsGrid = new Grid { ColumnSpacing = 16 };
        for (int i = 0; i < 4; i++)
            cardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var totalCard = CreateCard("Total Blocked", _totalBlockedText, _blockRateText);
        var dnsCard = CreateCard("DNS (UDP 53)", _dnsBlockedText, _dnsTotalText);
        var tlsCard = CreateCard("TLS SNI (TCP 443)", _tlsBlockedText, _tlsTotalText);
        var quicCard = CreateCard("QUIC (UDP 443)", _quicDroppedText, new TextBlock
        {
            Text = "Dropped -> TCP Fallback",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        });

        Grid.SetColumn(totalCard, 0);
        Grid.SetColumn(dnsCard, 1);
        Grid.SetColumn(tlsCard, 2);
        Grid.SetColumn(quicCard, 3);
        cardsGrid.Children.Add(totalCard);
        cardsGrid.Children.Add(dnsCard);
        cardsGrid.Children.Add(tlsCard);
        cardsGrid.Children.Add(quicCard);
        stack.Children.Add(cardsGrid);

        // Diagnostics Card
        var diagCard = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 32, 32, 36)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 48, 48, 54)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(20)
        };
        var diagStack = new StackPanel { Spacing = 12 };
        diagStack.Children.Add(new TextBlock
        {
            Text = "Engine IPC Status & Diagnostics",
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Colors.White)
        });

        var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        var pingBtn = new Button { Content = "Ping Engine", Style = Application.Current?.Resources["AccentButtonStyle"] as Style };
        pingBtn.Click += async (s, e) =>
        {
            _diagnosticsOutput.Text = "Pinging engine...";
            var sw = System.Diagnostics.Stopwatch.StartNew();
            bool ok = await _client.PingAsync();
            sw.Stop();
            _diagnosticsOutput.Text = ok ? $"Pong received! Latency: {sw.ElapsedMilliseconds} ms" : "Ping failed: engine unreachable.";
        };

        var resetBtn = new Button { Content = "Reset Stats" };
        resetBtn.Click += async (s, e) =>
        {
            await ViewModel.ResetStatsAsync();
            _diagnosticsOutput.Text = "Engine counters reset to 0.";
        };

        var refreshBtn = new Button { Content = "Refresh Status" };
        refreshBtn.Click += async (s, e) =>
        {
            await ViewModel.RefreshStatusAsync();
            await ViewModel.RefreshRulesAsync();
            _diagnosticsOutput.Text = $"Status refreshed: {ViewModel.StatusText}, {ViewModel.ActiveRulesCount} active rules.";
        };

        btnRow.Children.Add(pingBtn);
        btnRow.Children.Add(resetBtn);
        btnRow.Children.Add(refreshBtn);
        diagStack.Children.Add(btnRow);
        diagStack.Children.Add(_diagnosticsOutput);
        diagCard.Child = diagStack;
        stack.Children.Add(diagCard);

        scroll.Content = stack;
        return scroll;
    }

    private static Border CreateCard(string title, TextBlock valueBlock, TextBlock subtitleBlock)
    {
        var border = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 32, 32, 36)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 48, 48, 54)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16)
        };
        var cardStack = new StackPanel { Spacing = 6 };
        cardStack.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromArgb(200, 180, 180, 180))
        });
        cardStack.Children.Add(valueBlock);
        cardStack.Children.Add(subtitleBlock);
        border.Child = cardStack;
        return border;
    }

    private UIElement BuildQueryLogContent()
    {
        var grid = new Grid { Padding = new Thickness(16), RowSpacing = 12 };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var topBar = new Grid();
        topBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        topBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var info = new TextBlock
        {
            Text = "Real-time query and packet stream from WinDivert inspection loop",
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromArgb(200, 180, 180, 180)),
            VerticalAlignment = VerticalAlignment.Center
        };
        var clearBtn = new Button { Content = "Clear Log" };
        clearBtn.Click += (s, e) => ViewModel.ClearLogs();

        Grid.SetColumn(info, 0);
        Grid.SetColumn(clearBtn, 1);
        topBar.Children.Add(info);
        topBar.Children.Add(clearBtn);
        Grid.SetRow(topBar, 0);
        grid.Children.Add(topBar);

        // Customize log list view items
        _queryLogListView.ItemTemplate = null; // Display clean rows
        Grid.SetRow(_queryLogListView, 1);
        grid.Children.Add(_queryLogListView);

        return grid;
    }

    private UIElement BuildRulesContent()
    {
        var grid = new Grid { Padding = new Thickness(16), RowSpacing = 16 };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        // Input row
        var inputStack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        inputStack.Children.Add(_newRuleInput);

        var addBtn = new Button { Content = "Add Rule" };
        addBtn.Click += async (s, e) => await AddRuleFromInputAsync();
        inputStack.Children.Add(addBtn);

        var removeBtn = new Button { Content = "Remove Selected" };
        removeBtn.Click += async (s, e) =>
        {
            if (_rulesListView.SelectedItem is string selectedRule)
            {
                await _client.RemoveRulesAsync(new[] { selectedRule });
                await ViewModel.RefreshRulesAsync();
            }
        };
        inputStack.Children.Add(removeBtn);

        var clearBtn = new Button { Content = "Clear All" };
        clearBtn.Click += async (s, e) =>
        {
            await ViewModel.ClearAllRulesAsync();
            await ViewModel.RefreshRulesAsync();
        };
        inputStack.Children.Add(clearBtn);

        var importBtn = new Button { Content = "Import spec/rules.txt" };
        importBtn.Click += async (s, e) =>
        {
            string candidate = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "spec", "test-data", "rules.txt");
            if (!File.Exists(candidate)) candidate = "spec/test-data/rules.txt";
            if (File.Exists(candidate))
            {
                await ViewModel.ImportRulesFromFileAsync(candidate);
                _diagnosticsOutput.Text = $"Imported rules from {candidate}";
            }
            else
            {
                _diagnosticsOutput.Text = "Could not locate spec/test-data/rules.txt";
            }
        };
        inputStack.Children.Add(importBtn);

        Grid.SetRow(inputStack, 0);
        grid.Children.Add(inputStack);

        // Count row
        Grid.SetRow(_rulesCountHeader, 1);
        grid.Children.Add(_rulesCountHeader);

        // List
        Grid.SetRow(_rulesListView, 2);
        grid.Children.Add(_rulesListView);

        return grid;
    }

    private async Task AddRuleFromInputAsync()
    {
        string rule = _newRuleInput.Text.Trim();
        if (string.IsNullOrEmpty(rule) || !ViewModel.IsConnected) return;

        await _client.AddRulesAsync(new[] { rule });
        _newRuleInput.Text = "";
        await ViewModel.RefreshRulesAsync();
    }
}

