using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace AdblockApp.Services;

/// <summary>
/// Win32 clipboard helper for elevated (requireAdministrator) unpackaged WinUI 3 apps,
/// where the WinRT Clipboard broker can block Ctrl+V / ContextMenu paste from medium-integrity apps.
/// </summary>
public static class ClipboardHelper
{
    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;
    private const int VK_SHIFT = 0x10;
    private const int VK_CONTROL = 0x11;

    [DllImport("user32.dll")]
    private static extern short GetKeyState(int nVirtKey);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);

    private static bool IsKeyDown(int vk) => (GetKeyState(vk) & 0x8000) != 0;

    public static string? GetText()
    {
        if (!IsClipboardFormatAvailable(CF_UNICODETEXT))
            return null;

        if (!OpenClipboard(IntPtr.Zero))
            return null;

        try
        {
            IntPtr hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == IntPtr.Zero)
                return null;

            IntPtr ptr = GlobalLock(hData);
            if (ptr == IntPtr.Zero)
                return null;

            try
            {
                return Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                GlobalUnlock(hData);
            }
        }
        finally
        {
            CloseClipboard();
        }
    }

    public static bool SetText(string text)
    {
        if (!OpenClipboard(IntPtr.Zero))
            return false;

        try
        {
            EmptyClipboard();
            int bytes = (text.Length + 1) * 2;
            IntPtr hGlobal = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)bytes);
            if (hGlobal == IntPtr.Zero)
                return false;

            IntPtr target = GlobalLock(hGlobal);
            if (target == IntPtr.Zero)
            {
                GlobalFree(hGlobal);
                return false;
            }

            try
            {
                Marshal.Copy(text.ToCharArray(), 0, target, text.Length);
                Marshal.WriteInt16(target, text.Length * 2, 0);
            }
            finally
            {
                GlobalUnlock(hGlobal);
            }

            if (SetClipboardData(CF_UNICODETEXT, hGlobal) == IntPtr.Zero)
            {
                GlobalFree(hGlobal);
                return false;
            }

            return true;
        }
        finally
        {
            CloseClipboard();
        }
    }

    public static bool PasteIntoTextBox(TextBox textBox, Action<string>? onTextUpdated = null)
    {
        string? clip = GetText();
        if (string.IsNullOrEmpty(clip))
            return false;

        if (!textBox.AcceptsReturn)
        {
            clip = clip.Replace("\r", "").Replace("\n", "").Trim();
        }

        string current = textBox.Text ?? "";
        int start = Math.Clamp(textBox.SelectionStart, 0, current.Length);
        int length = Math.Clamp(textBox.SelectionLength, 0, current.Length - start);

        string updated = current.Substring(0, start) + clip + current.Substring(start + length);
        textBox.Text = updated;
        textBox.SelectionStart = start + clip.Length;
        textBox.SelectionLength = 0;

        onTextUpdated?.Invoke(updated);
        return true;
    }

    public static void AttachToTextBox(TextBox textBox, Action<string>? onTextUpdated = null)
    {
        textBox.TextChanged += (_, _) =>
        {
            onTextUpdated?.Invoke(textBox.Text ?? "");
        };

        textBox.Paste += (_, e) =>
        {
            if (PasteIntoTextBox(textBox, onTextUpdated))
            {
                e.Handled = true;
            }
        };

        textBox.PreviewKeyDown += (_, e) =>
        {
            bool ctrlDown = IsKeyDown(VK_CONTROL);
            bool shiftDown = IsKeyDown(VK_SHIFT);

            if ((ctrlDown && e.Key == VirtualKey.V) || (shiftDown && e.Key == VirtualKey.Insert))
            {
                if (PasteIntoTextBox(textBox, onTextUpdated))
                {
                    e.Handled = true;
                }
            }
            else if (ctrlDown && e.Key == VirtualKey.C)
            {
                if (!string.IsNullOrEmpty(textBox.SelectedText))
                {
                    SetText(textBox.SelectedText);
                    e.Handled = true;
                }
            }
            else if (ctrlDown && e.Key == VirtualKey.X)
            {
                if (!string.IsNullOrEmpty(textBox.SelectedText))
                {
                    SetText(textBox.SelectedText);
                    string current = textBox.Text ?? "";
                    int start = Math.Clamp(textBox.SelectionStart, 0, current.Length);
                    int length = Math.Clamp(textBox.SelectionLength, 0, current.Length - start);
                    string updated = current.Remove(start, length);
                    textBox.Text = updated;
                    textBox.SelectionStart = start;
                    textBox.SelectionLength = 0;
                    onTextUpdated?.Invoke(updated);
                    e.Handled = true;
                }
            }
        };

        var menu = new MenuFlyout();
        var pasteItem = new MenuFlyoutItem { Text = "Paste", Icon = new SymbolIcon(Symbol.Paste) };
        pasteItem.Click += (_, _) => PasteIntoTextBox(textBox, onTextUpdated);

        var copyItem = new MenuFlyoutItem { Text = "Copy", Icon = new SymbolIcon(Symbol.Copy) };
        copyItem.Click += (_, _) =>
        {
            if (!string.IsNullOrEmpty(textBox.SelectedText))
                SetText(textBox.SelectedText);
        };

        var clearItem = new MenuFlyoutItem { Text = "Clear", Icon = new SymbolIcon(Symbol.Delete) };
        clearItem.Click += (_, _) =>
        {
            textBox.Text = "";
            onTextUpdated?.Invoke("");
        };

        menu.Items.Add(pasteItem);
        menu.Items.Add(copyItem);
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(clearItem);
        textBox.ContextFlyout = menu;
    }
}
