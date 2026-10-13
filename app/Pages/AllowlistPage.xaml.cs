using AdblockApp.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace AdblockApp.Pages;

public sealed partial class AllowlistPage : Page
{
  public MainViewModel ViewModel => App.ViewModel;

  public AllowlistPage()
  {
    InitializeComponent();
  }

  private async void Add_Click(object sender, RoutedEventArgs e)
  {
    try { await ViewModel.AddAllowlistRuleAsync(); } catch { }
  }

  private async void Rule_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
  {
    if (e.Key != VirtualKey.Enter) return;
    e.Handled = true;
    try { await ViewModel.AddAllowlistRuleAsync(); } catch { }
  }

  private async void Remove_Click(object sender, RoutedEventArgs e)
  {
    if (((FrameworkElement)sender).Tag is string rule)
    {
      try { await ViewModel.RemoveAllowlistRuleAsync(rule); } catch { }
    }
  }

  private async void Clear_Click(object sender, RoutedEventArgs e)
  {
    var dialog = new ContentDialog
    {
      XamlRoot = XamlRoot,
      Title = "Clear allowlist?",
      Content = "All allowlist rules will be removed.",
      PrimaryButtonText = "Clear",
      CloseButtonText = "Cancel",
      DefaultButton = ContentDialogButton.Close
    };
    try
    {
      if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        await ViewModel.ClearAllowlistAsync();
    }
    catch { }
  }
}
