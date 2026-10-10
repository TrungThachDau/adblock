using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AdblockApp.Services;
using AdblockApp.ViewModels;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using Windows.UI;
using WinRT.Interop;

namespace AdblockApp;

public class MainWindow : Window
{
    public MainViewModel ViewModel { get; }
    private readonly EngineClient _client;
    private readonly ListManagerService _listManager;
    private readonly AllowlistService _allowlist;
    private readonly TrayIconService _trayIcon;

    // Header Controls
    private readonly TextBlock _engineBadge;
    private readonly TextBlock _statusSubtitle;
    private readonly ToggleSwitch _protectionToggle;

    // Dashboard Metric Controls
    private readonly TextBlock _totalBlockedText;
    private readonly TextBlock _blockRateText;
    private readonly TextBlock _dnsBlockedText;
    private readonly TextBlock _dnsTotalText;
    private readonly TextBlock _tlsBlockedText;
    private readonly TextBlock _tlsTotalText;
    private readonly TextBlock _quicDroppedText;
    private readonly TextBlock _engineMetaText;

    // Lists Controls
    private readonly TextBox _listUrlInput;
    private readonly TextBox _listNameInput;
    private readonly StackPanel _subscriptionsPanel;
    private readonly TextBlock _listsCountSummary;

    // Allowlist Controls
    private readonly TextBox _allowlistInput;
    private readonly StackPanel _allowlistPanel;
    private readonly TextBlock _allowlistCountSummary;

    // Recent Blocked Controls
    private readonly StackPanel _recentBlockedPanel;

    // Query Log Controls
    private readonly ListView _queryLogListView;

    private bool _isExplicitExit = false;

    public MainWindow()
    {
        this.Title = "Adblock Engine Monitor (WinDivert 2.x)";

        IntPtr hWnd = WindowNative.GetWindowHandle(this);
        SetWindowSize(hWnd, 1100, 780);

        _client = new EngineClient();
        _listManager = new ListManagerService(_client);
        _allowlist = new AllowlistService(_client);

        ViewModel = new MainViewModel(_client, _listManager, _allowlist, this.DispatcherQueue);

        // System Tray Integration
        _trayIcon = new TrayIconService(hWnd)
        {
            GetIsRunning = () => ViewModel.IsRunning,
            GetEngineName = () => $"{ViewModel.EngineName} {ViewModel.EngineVersion}".Trim(),
            ToggleProtectionAction = () =>
            {
                DispatcherQueue.TryEnqueue(async () => await ViewModel.ToggleProtectionAsync());
            },
            OpenDashboardAction = () =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    this.Activate();
                });
            },
            ExitAction = () =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    _isExplicitExit = true;
                    Application.Current.Exit();
                });
            }
        };

        // Window Close Interception (Hide to Tray instead of terminating)
        var appWindow = GetAppWindow(hWnd);
        if (appWindow != null)
        {
            appWindow.Closing += (s, e) =>
            {
                if (!_isExplicitExit)
                {
                    e.Cancel = true;
                    _trayIcon.HideWindow();
                    _trayIcon.ShowBalloon("Adblock Monitor", "Minimized to system tray. Filtering continues in background.");
                }
            };
        }

        // Initialize UI Elements
        _engineBadge = new TextBlock
        {
            Text = "DETECTING ENGINE",
            FontSize = 11,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 33, 150, 243)),
            VerticalAlignment = VerticalAlignment.Center
        };

        _statusSubtitle = new TextBlock
        {
            Text = "Connecting via Named Pipe...",
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

        // Metric TextBlocks
        _totalBlockedText = new TextBlock
        {
            Text = "0",
            FontSize = 30,
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
            FontSize = 30,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 0, 230, 118))
        };
        _dnsTotalText = new TextBlock
        {
            Text = "0 total queries",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        };

        _tlsBlockedText = new TextBlock
        {
            Text = "0",
            FontSize = 30,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 0, 229, 255))
        };
        _tlsTotalText = new TextBlock
        {
            Text = "0 total handshakes",
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
        };

        _quicDroppedText = new TextBlock
        {
            Text = "0",
            FontSize = 30,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromArgb(255, 255, 145, 0))
        };

        _engineMetaText = new TextBlock
        {
            Text = "Uptime: 0s  •  Active Rules: 0  •  Exceptions: 0  •  RAM: 0 MB",
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromArgb(220, 200, 200, 200))
        };

        // Lists Tab controls
        _listUrlInput = new TextBox { PlaceholderText = "Blocklist URL (e.g. https://...)", MinWidth = 380 };
        _listNameInput = new TextBox { PlaceholderText = "Optional Name (e.g. AdGuard Filter)", MinWidth = 200 };
        _subscriptionsPanel = new StackPanel { Spacing = 10 };
        _listsCountSummary = new TextBlock { Text = "0 Lists Configured", FontSize = 14, FontWeight = FontWeights.SemiBold };

        // Allowlist Tab controls
        _allowlistInput = new TextBox { PlaceholderText = "Domain or ABP rule (e.g. safe.domain.com, @@||cdn.net^)", MinWidth = 420 };
        _allowlistPanel = new StackPanel { Spacing = 8 };
        _allowlistCountSummary = new TextBlock { Text = "0 Allowlist Rules", FontSize = 14, FontWeight = FontWeights.SemiBold };

        // Recent Blocked
        _recentBlockedPanel = new StackPanel { Spacing = 8 };

        // Query Log
        _queryLogListView = new ListView
        {
            ItemsSource = ViewModel.QueryLogs,
            SelectionMode = ListViewSelectionMode.None
        };

        this.Content = BuildRootLayout();

        // Bind ViewModel Property Changes to UI Controls
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
                    case nameof(ViewModel.EngineName):
                    case nameof(ViewModel.EngineVersion):
                        string badge = $"{ViewModel.EngineName} {ViewModel.EngineVersion}".Trim().ToUpperInvariant();
                        _engineBadge.Text = string.IsNullOrEmpty(badge) ? "ENGINE" : badge;
                        _trayIcon.UpdateTooltip($"Adblock ({ViewModel.EngineName}) - {(ViewModel.IsRunning ? "Active" : "Paused")}");
                        break;
                    case nameof(ViewModel.IsRunning):
                        if (_protectionToggle.IsOn != ViewModel.IsRunning)
                            _protectionToggle.IsOn = ViewModel.IsRunning;
                        _trayIcon.UpdateTooltip($"Adblock ({ViewModel.EngineName}) - {(ViewModel.IsRunning ? "Active" : "Paused")}");
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
                        _dnsTotalText.Text = $"{ViewModel.DnsQueries:N0} total queries";
                        break;
                    case nameof(ViewModel.TlsBlocked):
                        _tlsBlockedText.Text = ViewModel.TlsBlocked.ToString("N0");
                        break;
                    case nameof(ViewModel.TlsQueries):
                        _tlsTotalText.Text = $"{ViewModel.TlsQueries:N0} total handshakes";
                        break;
                    case nameof(ViewModel.QuicDropped):
                        _quicDroppedText.Text = ViewModel.QuicDropped.ToString("N0");
                        break;
                    case nameof(ViewModel.ActiveRulesCount):
                    case nameof(ViewModel.AllowlistCount):
                    case nameof(ViewModel.RamMb):
                    case nameof(ViewModel.UptimeFormatted):
                        _engineMetaText.Text = $"Uptime: {ViewModel.UptimeFormatted}  •  Active Rules: {ViewModel.ActiveRulesCount:N0}  •  Exceptions: {ViewModel.AllowlistCount:N0}  •  RAM: {ViewModel.RamMb:F1} MB";
                        break;
                }
            });
        };

        // Update Subscriptions UI list when changed
        ViewModel.Subscriptions.CollectionChanged += (s, e) =>
        {
            DispatcherQueue.TryEnqueue(RebuildSubscriptionsUI);
        };

        // Update Allowlist UI list when changed
        ViewModel.AllowlistRules.CollectionChanged += (s, e) =>
        {
            DispatcherQueue.TryEnqueue(RebuildAllowlistUI);
        };

        // Update Recent Blocked UI list when changed
        ViewModel.RecentBlocked.CollectionChanged += (s, e) =>
        {
            DispatcherQueue.TryEnqueue(RebuildRecentBlockedUI);
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
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        // Header Bar (Row 0)
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
        titleStack.Children.Add(new TextBlock { Text = "🛡️", FontSize = 30, VerticalAlignment = VerticalAlignment.Center });

        var textStack = new StackPanel { Spacing = 3 };

        var badgeRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, VerticalAlignment = VerticalAlignment.Center };
        badgeRow.Children.Add(new TextBlock
        {
            Text = "Adblock Engine Monitor",
            FontSize = 20,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Colors.White)
        });

        var badgeBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(40, 33, 150, 243)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(120, 33, 150, 243)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(8, 2, 8, 2),
            VerticalAlignment = VerticalAlignment.Center,
            Child = _engineBadge
        };
        badgeRow.Children.Add(badgeBorder);

        textStack.Children.Add(badgeRow);
        textStack.Children.Add(_statusSubtitle);
        titleStack.Children.Add(textStack);

        Grid.SetColumn(titleStack, 0);
        Grid.SetColumn(_protectionToggle, 1);
        headerGrid.Children.Add(titleStack);
        headerGrid.Children.Add(_protectionToggle);
        headerBorder.Child = headerGrid;
        rootGrid.Children.Add(headerBorder);

        // Navigation Bar (Row 1)
        var navBar = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 28, 28, 32)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 42, 42, 48)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(24, 10, 24, 10)
        };
        Grid.SetRow(navBar, 1);

        var navStack = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 10
        };

        // Views Container (Row 2)
        var contentGrid = new Grid();
        Grid.SetRow(contentGrid, 2);

        var dashView = BuildDashboardContent();
        var listsView = BuildListsContent();
        var allowView = BuildAllowlistContent();
        var logsView = BuildQueryLogContent();

        dashView.Visibility = Visibility.Visible;
        listsView.Visibility = Visibility.Collapsed;
        allowView.Visibility = Visibility.Collapsed;
        logsView.Visibility = Visibility.Collapsed;

        contentGrid.Children.Add(dashView);
        contentGrid.Children.Add(listsView);
        contentGrid.Children.Add(allowView);
        contentGrid.Children.Add(logsView);

        // Navigation Tab Buttons
        var dashBtn = CreateNavTabButton("📊 Dashboard", true);
        var listsBtn = CreateNavTabButton("🛡️ Blocklists", false);
        var allowBtn = CreateNavTabButton("✅ Allowlist", false);
        var logsBtn = CreateNavTabButton("📋 Live Query Log", false);

        void SelectTab(int index)
        {
            dashView.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
            listsView.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
            allowView.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;
            logsView.Visibility = index == 3 ? Visibility.Visible : Visibility.Collapsed;

            UpdateNavTabStyle(dashBtn, index == 0);
            UpdateNavTabStyle(listsBtn, index == 1);
            UpdateNavTabStyle(allowBtn, index == 2);
            UpdateNavTabStyle(logsBtn, index == 3);
        }

        dashBtn.Click += (s, e) => SelectTab(0);
        listsBtn.Click += (s, e) => SelectTab(1);
        allowBtn.Click += (s, e) => SelectTab(2);
        logsBtn.Click += (s, e) => SelectTab(3);

        navStack.Children.Add(dashBtn);
        navStack.Children.Add(listsBtn);
        navStack.Children.Add(allowBtn);
        navStack.Children.Add(logsBtn);
        navBar.Child = navStack;

        rootGrid.Children.Add(navBar);
        rootGrid.Children.Add(contentGrid);
        return rootGrid;
    }

    private static Button CreateNavTabButton(string label, bool isActive)
    {
        var btn = new Button
        {
            Content = label,
            FontSize = 13,
            Padding = new Thickness(14, 6, 14, 6),
            CornerRadius = new CornerRadius(6)
        };
        UpdateNavTabStyle(btn, isActive);
        return btn;
    }

    private static void UpdateNavTabStyle(Button btn, bool isActive)
    {
        btn.FontWeight = isActive ? FontWeights.SemiBold : FontWeights.Normal;
        btn.Background = new SolidColorBrush(isActive ? Color.FromArgb(255, 33, 150, 243) : Color.FromArgb(0, 0, 0, 0));
        btn.Foreground = new SolidColorBrush(isActive ? Colors.White : Color.FromArgb(200, 200, 200, 200));
        btn.BorderBrush = new SolidColorBrush(isActive ? Color.FromArgb(255, 33, 150, 243) : Color.FromArgb(50, 255, 255, 255));
        btn.BorderThickness = new Thickness(1);
    }

    private UIElement BuildDashboardContent()
    {
        var scroll = new ScrollViewer { Padding = new Thickness(16) };
        var stack = new StackPanel { Spacing = 20 };

        // Engine Status & Meta Card
        var metaBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 32, 32, 36)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 48, 48, 54)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16)
        };
        var metaGrid = new Grid();
        metaGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        metaGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        metaGrid.Children.Add(_engineMetaText);
        Grid.SetColumn(_engineMetaText, 0);

        var actionsStack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var pingBtn = new Button { Content = "Ping" };
        pingBtn.Click += async (s, e) =>
        {
            bool ok = await _client.PingAsync();
            _statusSubtitle.Text = ok ? "Ping successful (engine reachable)." : "Ping failed: engine not responding.";
        };
        var resetBtn = new Button { Content = "Reset Stats" };
        resetBtn.Click += async (s, e) => await ViewModel.ResetStatsAsync();

        var refreshBtn = new Button { Content = "Refresh Status" };
        refreshBtn.Click += async (s, e) => await ViewModel.RefreshStatusAsync();

        actionsStack.Children.Add(pingBtn);
        actionsStack.Children.Add(resetBtn);
        actionsStack.Children.Add(refreshBtn);
        Grid.SetColumn(actionsStack, 1);
        metaGrid.Children.Add(actionsStack);
        metaBorder.Child = metaGrid;
        stack.Children.Add(metaBorder);

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

        // Recent Blocked Section
        var recentHeader = new Grid { Margin = new Thickness(0, 10, 0, 0) };
        recentHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        recentHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var recentTitle = new TextBlock
        {
            Text = "Recent Blocked Queries",
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Colors.White)
        };
        var clearRecentBtn = new Button { Content = "Clear" };
        clearRecentBtn.Click += (s, e) => ViewModel.ClearRecentBlocked();

        Grid.SetColumn(recentTitle, 0);
        Grid.SetColumn(clearRecentBtn, 1);
        recentHeader.Children.Add(recentTitle);
        recentHeader.Children.Add(clearRecentBtn);
        stack.Children.Add(recentHeader);

        stack.Children.Add(_recentBlockedPanel);
        RebuildRecentBlockedUI();

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

    private void RebuildRecentBlockedUI()
    {
        _recentBlockedPanel.Children.Clear();

        if (ViewModel.RecentBlocked.Count == 0)
        {
            _recentBlockedPanel.Children.Add(new TextBlock
            {
                Text = "No blocked queries recorded yet. Blocked DNS and TLS connections will appear here in real-time.",
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromArgb(160, 160, 160, 160)),
                Margin = new Thickness(0, 12, 0, 0)
            });
            return;
        }

        foreach (var item in ViewModel.RecentBlocked.Take(30))
        {
            var rowBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(255, 30, 30, 34)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(255, 42, 42, 48)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(14, 10, 14, 10)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });  // Time
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(60) });  // Proto
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // Domain & Rule
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // Allow Button

            var timeBlock = new TextBlock
            {
                Text = item.TimeFormatted,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160)),
                VerticalAlignment = VerticalAlignment.Center
            };

            bool isDns = item.Protocol.Equals("DNS", StringComparison.OrdinalIgnoreCase);
            var protoBadge = new Border
            {
                Background = new SolidColorBrush(isDns ? Color.FromArgb(40, 0, 230, 118) : Color.FromArgb(40, 0, 229, 255)),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(6, 2, 6, 2),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = item.Protocol,
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(isDns ? Color.FromArgb(255, 0, 230, 118) : Color.FromArgb(255, 0, 229, 255))
                }
            };

            var detailStack = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
            detailStack.Children.Add(new TextBlock
            {
                Text = item.Domain,
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(Colors.White)
            });

            string reason = string.IsNullOrEmpty(item.MatchedRule) ? "Matched ad/tracker blocklist" : item.MatchedRule;
            detailStack.Children.Add(new TextBlock
            {
                Text = reason,
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromArgb(180, 255, 110, 110))
            });

            var allowBtn = new Button
            {
                Content = "Allow",
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            };
            allowBtn.Click += async (s, e) =>
            {
                await ViewModel.AllowBlockedDomainAsync(item.Domain);
                allowBtn.Content = "Allowed ✓";
                allowBtn.IsEnabled = false;
            };

            Grid.SetColumn(timeBlock, 0);
            Grid.SetColumn(protoBadge, 1);
            Grid.SetColumn(detailStack, 2);
            Grid.SetColumn(allowBtn, 3);

            grid.Children.Add(timeBlock);
            grid.Children.Add(protoBadge);
            grid.Children.Add(detailStack);
            grid.Children.Add(allowBtn);

            rowBorder.Child = grid;
            _recentBlockedPanel.Children.Add(rowBorder);
        }
    }

    private UIElement BuildListsContent()
    {
        var scroll = new ScrollViewer { Padding = new Thickness(16) };
        var stack = new StackPanel { Spacing = 20 };

        // Add subscription card
        var addCard = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 32, 32, 36)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 48, 48, 54)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(18)
        };
        var addStack = new StackPanel { Spacing = 12 };
        addStack.Children.Add(new TextBlock
        {
            Text = "Add Blocklist Subscription URL",
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Colors.White)
        });

        var inputRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        inputRow.Children.Add(_listUrlInput);
        inputRow.Children.Add(_listNameInput);

        var addBtn = new Button { Content = "Add & Download" };
        addBtn.Click += async (s, e) =>
        {
            string url = _listUrlInput.Text.Trim();
            string name = _listNameInput.Text.Trim();
            if (string.IsNullOrEmpty(url)) return;

            addBtn.IsEnabled = false;
            addBtn.Content = "Downloading...";
            await _listManager.AddListAsync(name, url);
            _listUrlInput.Text = "";
            _listNameInput.Text = "";
            addBtn.Content = "Add & Download";
            addBtn.IsEnabled = true;
            await ViewModel.RefreshStatusAsync();
        };
        inputRow.Children.Add(addBtn);

        var updateAllBtn = new Button { Content = "Update All Lists" };
        updateAllBtn.Click += async (s, e) =>
        {
            updateAllBtn.IsEnabled = false;
            updateAllBtn.Content = "Updating All...";
            await ViewModel.UpdateAllSubscriptionsAsync();
            updateAllBtn.Content = "Update All Lists";
            updateAllBtn.IsEnabled = true;
        };
        inputRow.Children.Add(updateAllBtn);

        addStack.Children.Add(inputRow);
        addCard.Child = addStack;
        stack.Children.Add(addCard);

        // Subscriptions List
        stack.Children.Add(_listsCountSummary);
        stack.Children.Add(_subscriptionsPanel);
        RebuildSubscriptionsUI();

        scroll.Content = stack;
        return scroll;
    }

    private void RebuildSubscriptionsUI()
    {
        _subscriptionsPanel.Children.Clear();
        _listsCountSummary.Text = $"{ViewModel.Subscriptions.Count} Blocklist Subscriptions ({ViewModel.Subscriptions.Count(s => s.IsEnabled)} enabled)";

        if (ViewModel.Subscriptions.Count == 0)
        {
            _subscriptionsPanel.Children.Add(new TextBlock
            {
                Text = "No blocklists configured. Add a subscription URL above.",
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromArgb(160, 160, 160, 160))
            });
            return;
        }

        foreach (var sub in ViewModel.Subscriptions)
        {
            var itemBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(255, 30, 30, 34)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(255, 42, 42, 48)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(16, 12, 16, 12)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // Toggle
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // Info
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // Actions

            var toggle = new ToggleSwitch
            {
                IsOn = sub.IsEnabled,
                Margin = new Thickness(0, 0, 16, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            toggle.Toggled += async (s, e) =>
            {
                if (toggle.IsOn != sub.IsEnabled)
                {
                    await _listManager.ToggleListAsync(sub.Id, toggle.IsOn);
                    await ViewModel.RefreshStatusAsync();
                }
            };

            var infoStack = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
            infoStack.Children.Add(new TextBlock
            {
                Text = sub.Name,
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(Colors.White)
            });

            string meta = $"{sub.RuleCount:N0} rules  •  {sub.Status}";
            if (sub.LastUpdated.HasValue)
            {
                meta += $"  •  Updated {sub.LastUpdated.Value:g}";
            }
            infoStack.Children.Add(new TextBlock
            {
                Text = meta,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromArgb(180, 160, 160, 160))
            });
            infoStack.Children.Add(new TextBlock
            {
                Text = sub.Url,
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromArgb(140, 140, 140, 140))
            });

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
            var updateBtn = new Button { Content = "Update" };
            updateBtn.Click += async (s, e) =>
            {
                updateBtn.IsEnabled = false;
                updateBtn.Content = "Updating...";
                await _listManager.UpdateListAsync(sub.Id);
                await ViewModel.RefreshStatusAsync();
            };

            var deleteBtn = new Button { Content = "Delete" };
            deleteBtn.Click += async (s, e) =>
            {
                await _listManager.DeleteListAsync(sub.Id);
                await ViewModel.RefreshStatusAsync();
            };

            btnRow.Children.Add(updateBtn);
            btnRow.Children.Add(deleteBtn);

            Grid.SetColumn(toggle, 0);
            Grid.SetColumn(infoStack, 1);
            Grid.SetColumn(btnRow, 2);

            grid.Children.Add(toggle);
            grid.Children.Add(infoStack);
            grid.Children.Add(btnRow);

            itemBorder.Child = grid;
            _subscriptionsPanel.Children.Add(itemBorder);
        }
    }

    private UIElement BuildAllowlistContent()
    {
        var scroll = new ScrollViewer { Padding = new Thickness(16) };
        var stack = new StackPanel { Spacing = 20 };

        // Add Allowlist Card
        var addCard = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(255, 32, 32, 36)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(255, 48, 48, 54)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(18)
        };
        var addStack = new StackPanel { Spacing = 12 };
        addStack.Children.Add(new TextBlock
        {
            Text = "Add Custom Allowlist Rule / Exception",
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Colors.White)
        });

        var inputRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        inputRow.Children.Add(_allowlistInput);

        var addBtn = new Button { Content = "Add Exception" };
        addBtn.Click += async (s, e) =>
        {
            string rule = _allowlistInput.Text.Trim();
            if (string.IsNullOrEmpty(rule)) return;

            await _allowlist.AddRuleAsync(rule);
            _allowlistInput.Text = "";
            await ViewModel.RefreshStatusAsync();
        };
        inputRow.Children.Add(addBtn);

        var clearBtn = new Button { Content = "Clear All" };
        clearBtn.Click += async (s, e) =>
        {
            await _allowlist.ClearRulesAsync();
            await ViewModel.RefreshStatusAsync();
        };
        inputRow.Children.Add(clearBtn);

        addStack.Children.Add(inputRow);
        addCard.Child = addStack;
        stack.Children.Add(addCard);

        // Allowlist Rules
        stack.Children.Add(_allowlistCountSummary);
        stack.Children.Add(_allowlistPanel);
        RebuildAllowlistUI();

        scroll.Content = stack;
        return scroll;
    }

    private void RebuildAllowlistUI()
    {
        _allowlistPanel.Children.Clear();
        _allowlistCountSummary.Text = $"{ViewModel.AllowlistRules.Count} Allowlist Exceptions";

        if (ViewModel.AllowlistRules.Count == 0)
        {
            _allowlistPanel.Children.Add(new TextBlock
            {
                Text = "No allowlist rules configured. Add domain exceptions above.",
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromArgb(160, 160, 160, 160))
            });
            return;
        }

        foreach (var rule in ViewModel.AllowlistRules)
        {
            var itemBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(255, 30, 30, 34)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(255, 42, 42, 48)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(14, 8, 14, 8)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var text = new TextBlock
            {
                Text = rule,
                FontSize = 13,
                FontWeight = FontWeights.Medium,
                Foreground = new SolidColorBrush(Color.FromArgb(255, 0, 230, 118)),
                VerticalAlignment = VerticalAlignment.Center
            };

            var removeBtn = new Button
            {
                Content = "Remove",
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            };
            removeBtn.Click += async (s, e) =>
            {
                await _allowlist.RemoveRuleAsync(rule);
                await ViewModel.RefreshStatusAsync();
            };

            Grid.SetColumn(text, 0);
            Grid.SetColumn(removeBtn, 1);
            grid.Children.Add(text);
            grid.Children.Add(removeBtn);

            itemBorder.Child = grid;
            _allowlistPanel.Children.Add(itemBorder);
        }
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
            Text = "Real-time query and packet stream intercepted by WinDivert 2.x kernel driver",
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

        Grid.SetRow(_queryLogListView, 1);
        grid.Children.Add(_queryLogListView);

        return grid;
    }

    private static AppWindow? GetAppWindow(IntPtr hWnd)
    {
        Microsoft.UI.WindowId windowId = Win32Interop.GetWindowIdFromWindow(hWnd);
        return AppWindow.GetFromWindowId(windowId);
    }

    private static void SetWindowSize(IntPtr hWnd, int width, int height)
    {
        var appWindow = GetAppWindow(hWnd);
        if (appWindow != null)
        {
            appWindow.Resize(new SizeInt32(width, height));
        }
    }
}
