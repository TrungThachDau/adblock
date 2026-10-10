using System;
using System.Runtime.InteropServices;

namespace AdblockApp.Services;

public class TrayIconService : IDisposable
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    private delegate IntPtr SubclassProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, UIntPtr uIdSubclass, IntPtr dwRefData);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Shell_NotifyIconW(int dwMessage, ref NOTIFYICONDATAW lpData);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, UIntPtr uIDNewItem, string lpNewItem);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint TrackPopupMenuEx(IntPtr hmenu, uint fuFlags, int x, int y, IntPtr hwnd, IntPtr lptpm);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("comctl32.dll", SetLastError = true)]
    private static extern bool SetWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, UIntPtr uIdSubclass, IntPtr dwRefData);

    [DllImport("comctl32.dll", SetLastError = true)]
    private static extern IntPtr DefSubclassProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    [DllImport("comctl32.dll", SetLastError = true)]
    private static extern bool RemoveWindowSubclass(IntPtr hWnd, SubclassProc pfnSubclass, UIntPtr uIdSubclass);

    private const int NIM_ADD = 0x00000000;
    private const int NIM_MODIFY = 0x00000001;
    private const int NIM_DELETE = 0x00000002;

    private const int NIF_MESSAGE = 0x00000001;
    private const int NIF_ICON = 0x00000002;
    private const int NIF_TIP = 0x00000004;
    private const int NIF_INFO = 0x00000010;

    private const uint WM_USER = 0x0400;
    private const uint WM_TRAYICON = WM_USER + 102;

    private const int WM_LBUTTONUP = 0x0202;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_RBUTTONUP = 0x0205;

    private const uint MF_STRING = 0x00000000;
    private const uint MF_GRAYED = 0x00000001;
    private const uint MF_SEPARATOR = 0x00000800;

    private const uint TPM_RETURNCMD = 0x0100;
    private const uint TPM_RIGHTBUTTON = 0x0002;

    private const int SW_HIDE = 0;
    private const int SW_RESTORE = 9;

    private static readonly IntPtr IDI_SHIELD = new IntPtr(32518);
    private static readonly IntPtr IDI_APPLICATION = new IntPtr(32512);

    private readonly IntPtr _hWnd;
    private readonly SubclassProc _subclassProc;
    private NOTIFYICONDATAW _nid;
    private bool _isCreated;

    public Func<bool>? GetIsRunning { get; set; }
    public Func<string>? GetEngineName { get; set; }
    public Action? ToggleProtectionAction { get; set; }
    public Action? OpenDashboardAction { get; set; }
    public Action? ExitAction { get; set; }

    public TrayIconService(IntPtr hWnd)
    {
        _hWnd = hWnd;
        _subclassProc = WindowSubclassProc;

        SetWindowSubclass(_hWnd, _subclassProc, new UIntPtr(101), IntPtr.Zero);
        InitializeTrayIcon();
    }

    private void InitializeTrayIcon()
    {
        IntPtr hIcon = LoadIcon(IntPtr.Zero, IDI_SHIELD);
        if (hIcon == IntPtr.Zero)
        {
            hIcon = LoadIcon(IntPtr.Zero, IDI_APPLICATION);
        }

        _nid = new NOTIFYICONDATAW
        {
            cbSize = Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = _hWnd,
            uID = 1001,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = (int)WM_TRAYICON,
            hIcon = hIcon,
            szTip = "Adblock Engine (WinDivert 2.x)"
        };

        _isCreated = Shell_NotifyIconW(NIM_ADD, ref _nid);
    }

    public void UpdateTooltip(string tooltip)
    {
        if (!_isCreated) return;
        _nid.szTip = tooltip.Length > 127 ? tooltip.Substring(0, 127) : tooltip;
        _nid.uFlags = NIF_TIP;
        Shell_NotifyIconW(NIM_MODIFY, ref _nid);
    }

    public void ShowBalloon(string title, string text)
    {
        if (!_isCreated) return;
        _nid.uFlags = NIF_INFO;
        _nid.szInfoTitle = title.Length > 63 ? title.Substring(0, 63) : title;
        _nid.szInfo = text.Length > 255 ? text.Substring(0, 255) : text;
        _nid.dwInfoFlags = 0x00000001; // NIIF_INFO
        Shell_NotifyIconW(NIM_MODIFY, ref _nid);
    }

    public void RestoreWindow()
    {
        ShowWindow(_hWnd, SW_RESTORE);
        SetForegroundWindow(_hWnd);
        OpenDashboardAction?.Invoke();
    }

    public void HideWindow()
    {
        ShowWindow(_hWnd, SW_HIDE);
    }

    private IntPtr WindowSubclassProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, UIntPtr uIdSubclass, IntPtr dwRefData)
    {
        if (uMsg == WM_TRAYICON)
        {
            int mouseMsg = lParam.ToInt32();
            if (mouseMsg == WM_LBUTTONUP || mouseMsg == WM_LBUTTONDBLCLK)
            {
                RestoreWindow();
                return IntPtr.Zero;
            }
            else if (mouseMsg == WM_RBUTTONUP)
            {
                ShowContextMenu();
                return IntPtr.Zero;
            }
        }

        return DefSubclassProc(hWnd, uMsg, wParam, lParam);
    }

    private void ShowContextMenu()
    {
        bool isRunning = GetIsRunning?.Invoke() ?? false;
        string engineName = GetEngineName?.Invoke() ?? "";

        IntPtr menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING | MF_GRAYED, new UIntPtr(1), "🛡️ Adblock Monitor");
        AppendMenuW(menu, MF_STRING | MF_GRAYED, new UIntPtr(2), isRunning ? "● Protection Active" : "○ Protection Paused");
        if (!string.IsNullOrEmpty(engineName))
        {
            AppendMenuW(menu, MF_STRING | MF_GRAYED, new UIntPtr(3), $"Engine: {engineName}");
        }
        AppendMenuW(menu, MF_SEPARATOR, UIntPtr.Zero, "");
        AppendMenuW(menu, MF_STRING, new UIntPtr(1001), isRunning ? "Pause Protection" : "Resume Protection");
        AppendMenuW(menu, MF_STRING, new UIntPtr(1002), "Open Dashboard");
        AppendMenuW(menu, MF_SEPARATOR, UIntPtr.Zero, "");
        AppendMenuW(menu, MF_STRING, new UIntPtr(1003), "Exit");

        GetCursorPos(out var pt);
        SetForegroundWindow(_hWnd);
        uint cmd = TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.X, pt.Y, _hWnd, IntPtr.Zero);
        DestroyMenu(menu);

        if (cmd == 1001)
        {
            ToggleProtectionAction?.Invoke();
        }
        else if (cmd == 1002)
        {
            RestoreWindow();
        }
        else if (cmd == 1003)
        {
            ExitAction?.Invoke();
        }
    }

    public void Dispose()
    {
        if (_isCreated)
        {
            Shell_NotifyIconW(NIM_DELETE, ref _nid);
            _isCreated = false;
        }
        RemoveWindowSubclass(_hWnd, _subclassProc, new UIntPtr(101));
    }
}

