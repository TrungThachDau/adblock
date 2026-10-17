using AdblockApp.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AdblockApp.Pages;

public sealed partial class DashboardPage : Page
{
  public MainViewModel ViewModel => App.ViewModel;

  public DashboardPage()
  {
    InitializeComponent();
  }

  private async void StartupToggle_Toggled(object sender, RoutedEventArgs e)
  {
    if (StartupToggle.IsOn == ViewModel.RunOnStartup) return;
    try { await ViewModel.SetStartupAsync(StartupToggle.IsOn); }
    catch { }
    StartupToggle.IsOn = ViewModel.RunOnStartup;
  }

  private async void ProtectionToggle_Toggled(object sender, RoutedEventArgs e)
  {
    if (ProtectionToggle.IsOn == ViewModel.IsRunning) return;
    try { await ViewModel.ToggleProtectionAsync(); }
    catch { }
    // Snap back to the engine's real state if the command failed.
    ProtectionToggle.IsOn = ViewModel.IsRunning;
  }

  private async void Allow_Click(object sender, RoutedEventArgs e)
  {
    if (((FrameworkElement)sender).Tag is string domain)
    {
      try { await ViewModel.AllowBlockedDomainAsync(domain); }
      catch { }
    }
  }
}
