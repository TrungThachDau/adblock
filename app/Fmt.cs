using System;
using Microsoft.UI.Xaml;

namespace AdblockApp;

// Function-binding helpers for x:Bind.
public static class Fmt
{
  public static bool Not(bool v) => !v;
  public static Visibility Vis(bool v) => v ? Visibility.Visible : Visibility.Collapsed;
  public static Visibility VisNot(bool v) => v ? Visibility.Collapsed : Visibility.Visible;
  public static Visibility VisWhenEmpty(int count) => count == 0 ? Visibility.Visible : Visibility.Collapsed;
  public static string Num(long v) => v.ToString("N0");
  public static string Percent(double v) => $"{v:F1}%";
  public static string Mb(double v) => $"{v:F1} MB";
  public static string State(bool running) => running ? "Running" : "Stopped";
  public static string Updated(DateTime? d) => d is null ? "Never updated" : $"Updated {d.Value:g}";
  public static string RuleCount(int n) => $"{n:N0} rules";
  public static string QueryTotal(long n, string what) => $"{n:N0} {what}";
}
