using AdblockApp.Services;
using AdblockApp.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace AdblockApp.Pages;

public sealed partial class ListsPage : Page
{
  public MainViewModel ViewModel => App.ViewModel;

  public ListsPage()
  {
    InitializeComponent();
  }

  private static BlocklistSubscription? Sub(object sender) => (sender as FrameworkElement)?.DataContext as BlocklistSubscription;

  private async void Add_Click(object sender, RoutedEventArgs e)
  {
    try { await ViewModel.AddSubscriptionAsync(); } catch { }
  }

  private async void Url_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
  {
    if (e.Key != VirtualKey.Enter) return;
    e.Handled = true;
    try { await ViewModel.AddSubscriptionAsync(); } catch { }
  }

  private async void ManualDomain_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
  {
    if (e.Key != VirtualKey.Enter) return;
    e.Handled = true;
    try { await ViewModel.AddManualBlockDomainAsync(); } catch { }
  }

  private async void RemoveManualDomain_Click(object sender, RoutedEventArgs e)
  {
    if (sender is not Button { Tag: string domain }) return;
    try { await ViewModel.RemoveManualBlockDomainAsync(domain); } catch { }
  }

  private async void Toggle_Toggled(object sender, RoutedEventArgs e)
  {
    // Toggled also fires when the template binds the initial value.
    if (Sub(sender) is { } sub && sender is ToggleSwitch ts && ts.IsOn != sub.IsEnabled)
    {
      try { await ViewModel.ToggleSubscriptionAsync(sub.Id); } catch { }
    }
  }

  private async void Update_Click(object sender, RoutedEventArgs e)
  {
    if (Sub(sender) is { } sub)
    {
      try { await ViewModel.UpdateSubscriptionAsync(sub.Id); } catch { }
    }
  }

  private async void Delete_Click(object sender, RoutedEventArgs e)
  {
    if (Sub(sender) is not { } sub) return;
    var dialog = new ContentDialog
    {
      XamlRoot = XamlRoot,
      Title = "Delete blocklist?",
      Content = sub.Name,
      PrimaryButtonText = "Delete",
      CloseButtonText = "Cancel",
      DefaultButton = ContentDialogButton.Close
    };
    try
    {
      if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        await ViewModel.DeleteSubscriptionAsync(sub.Id);
    }
    catch { }
  }
}
