using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using AdblockApp.Services;
using AdblockApp.ViewModels;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using WinRT.Interop;

namespace AdblockApp;

public sealed partial class MainWindow : Window
{
  [DllImport("user32.dll")]
  private static extern uint GetDpiForWindow(IntPtr hWnd);

  public MainViewModel ViewModel => App.ViewModel;

  private readonly TrayIconService _tray;
  private bool _isExplicitExit;

  public MainWindow()
  {
    InitializeComponent();
    Title = "Adblock";
    ExtendsContentIntoTitleBar = true;
    SetTitleBar(AppTitleBar);

    IntPtr hWnd = WindowNative.GetWindowHandle(this);
    uint dpi = GetDpiForWindow(hWnd);
    double scale = dpi == 0 ? 1.0 : dpi / 96.0;
    AppWindow.Resize(new Windows.Graphics.SizeInt32((int)(1100 * scale), (int)(760 * scale)));

    _tray = new TrayIconService(hWnd)
    {
      GetIsRunning = () => ViewModel.IsRunning,
      GetRunOnStartup = () => ViewModel.RunOnStartup,
      GetEngineName = () => $"{ViewModel.EngineName} {ViewModel.EngineVersion}".Trim(),
      ToggleProtectionAction = () => DispatcherQueue.TryEnqueue(async () =>
      {
        try { await ViewModel.ToggleProtectionAsync(); } catch { }
      }),
      ToggleStartupAction = () => DispatcherQueue.TryEnqueue(async () =>
      {
        try { await ViewModel.ToggleStartupAsync(); } catch { }
      }),
      OpenDashboardAction = () => DispatcherQueue.TryEnqueue(() => Activate()),
      ExitAction = () => DispatcherQueue.TryEnqueue(() =>
      {
        _isExplicitExit = true;
        Close();
      })
    };

    AppWindow.Closing += (_, e) =>
    {
      if (_isExplicitExit) return;
      e.Cancel = true;
      _tray.HideWindow();
      _tray.ShowBalloon("Adblock", "Still running in the system tray.");
    };

    Closed += (_, _) =>
    {
      _tray.Dispose();
      App.Client.Dispose();
    };

    ViewModel.PropertyChanged += OnViewModelPropertyChanged;
    UpdateTrayTooltip();

    Nav.SelectedItem = Nav.MenuItems[0];
  }

  public static Brush StatusBrush(bool connected) =>
      (Brush)Application.Current.Resources[connected ? "SystemFillColorSuccessBrush" : "SystemFillColorCriticalBrush"];

  private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
  {
    if (e.PropertyName is nameof(MainViewModel.IsRunning) or nameof(MainViewModel.EngineName) or nameof(MainViewModel.IsConnected))
      UpdateTrayTooltip();
  }

  private void UpdateTrayTooltip()
  {
    string state = !ViewModel.IsConnected ? "Disconnected" : ViewModel.IsRunning ? "Active" : "Paused";
    _tray.UpdateTooltip($"Adblock ({ViewModel.EngineName}) - {state}");
  }

  private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
  {
    Type? page = (args.SelectedItem as NavigationViewItem)?.Tag switch
    {
      "dashboard" => typeof(Pages.DashboardPage),
      "lists" => typeof(Pages.ListsPage),
      "allowlist" => typeof(Pages.AllowlistPage),
      "dns" => typeof(Pages.PrivateDnsPage),
      _ => null
    };
    if (page != null && ContentFrame.CurrentSourcePageType != page)
      ContentFrame.Navigate(page);
  }
}
