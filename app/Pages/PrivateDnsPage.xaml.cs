using AdblockApp.Services;
using AdblockApp.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace AdblockApp.Pages;

public sealed partial class PrivateDnsPage : Page
{
  public MainViewModel ViewModel => App.ViewModel;

  public PrivateDnsPage()
  {
    InitializeComponent();
    ClipboardHelper.AttachToTextBox(DnsUrlTextBox, text => ViewModel.PrivateDnsUrl = text);
  }

  private void SyncTextBoxToViewModel()
  {
    ViewModel.PrivateDnsUrl = DnsUrlTextBox.Text ?? "";
  }

  private async void Test_Click(object sender, RoutedEventArgs e)
  {
    SyncTextBoxToViewModel();
    try
    {
      await ViewModel.TestPrivateDnsAsync();
    }
    catch { }
  }

  private async void PrivateDnsToggle_Toggled(object sender, RoutedEventArgs e)
  {
    if (PrivateDnsToggle.IsOn == ViewModel.PrivateDnsEnabled) return;
    SyncTextBoxToViewModel();
    try
    {
      await ViewModel.SetPrivateDnsEnabledAsync(PrivateDnsToggle.IsOn);
    }
    catch { }
    PrivateDnsToggle.IsOn = ViewModel.PrivateDnsEnabled;
  }

  private async void Save_Click(object sender, RoutedEventArgs e)
  {
    SyncTextBoxToViewModel();
    try
    {
      await ViewModel.SavePrivateDnsAsync();
    }
    catch { }
    PrivateDnsToggle.IsOn = ViewModel.PrivateDnsEnabled;
  }

  private async void Url_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
  {
    if (e.Key != VirtualKey.Enter) return;
    e.Handled = true;
    SyncTextBoxToViewModel();
    try
    {
      await ViewModel.SavePrivateDnsAsync();
    }
    catch { }
    PrivateDnsToggle.IsOn = ViewModel.PrivateDnsEnabled;
  }
}
