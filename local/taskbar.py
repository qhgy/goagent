#!/usr/bin/env python
# coding:utf-8

# Creates a task-bar icon with balloon tip.  Run from Python.exe to see the
# messages printed.  Right click for balloon tip.  Double click to exit.
# original version of this demo available at http://www.itamarst.org/software/
import pywintypes, win32api, win32con, win32gui, win32process
import sys, os, ctypes

WM_TASKBARNOTIFY = win32con.WM_USER+20
WM_TASKBARNOTIFY_MENUITEM_SHOW = win32con.WM_USER + 21
WM_TASKBARNOTIFY_MENUITEM_HIDE = win32con.WM_USER + 22
WM_TASKBARNOTIFY_MENUITEM_EXIT = win32con.WM_USER + 23
class Taskbar(object):
    def __init__(self, cmd, icon, tooltip):
        self.cmd = cmd
        self.icon = icon
        message_map = {
            win32con.WM_DESTROY: self.onDestroy,
            win32con.WM_COMMAND: self.onCommand,
            WM_TASKBARNOTIFY : self.onTaskbarNotify,
        }
        # Register the Window class.
        wc = win32gui.WNDCLASS()
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "PythonTaskbarDemo"
        wc.style = win32con.CS_VREDRAW | win32con.CS_HREDRAW;
        wc.hCursor = win32gui.LoadCursor(0, win32con.IDC_ARROW)
        wc.hbrBackground = win32con.COLOR_WINDOW
        wc.lpfnWndProc = message_map # could also specify a wndproc.
        classAtom = win32gui.RegisterClass(wc)
        # Create the Window.
        style = win32con.WS_OVERLAPPED | win32con.WS_SYSMENU
        self.hwnd = win32gui.CreateWindow( classAtom, "Taskbar Demo", style, \
                    0, 0, win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT, \
                    0, 0, wc.hInstance, None)
        win32gui.UpdateWindow(self.hwnd)

        hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcess(None, self.cmd, None, None, 0, 0, None, None, win32process.STARTUPINFO())
        self.hProcess = hProcess
        try:
            hicon = pywintypes.HANDLE(win32gui.ExtractIconEx(win32api.GetModuleFileName(0), 0)[1][0])
        except IndexError:
            hicon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
        self.hicon = hicon
        self.tooltip = tooltip
        self.show()

    def show(self):
        """Display the taskbar icon"""
        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE
        if self.tooltip is not None:
            flags |= win32gui.NIF_TIP
            nid = (self.hwnd, 0, flags, WM_TASKBARNOTIFY, self.hicon, self.tooltip)
        else:
            nid = (self.hwnd, 0, flags, WM_TASKBARNOTIFY, self.hicon)
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, nid)
        self.visible = 1

    def hide(self):
        """Hide the taskbar icon"""
        if self.visible:
            nid = (self.hwnd, 0)
            win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, nid)
        self.visible = 0

    def onDestroy(self, hwnd, msg, wparam, lparam):
        self.hide()
        win32gui.PostQuitMessage(0) # Terminate the app.

    def onTaskbarNotify(self, hwnd, msg, wparam, lparam):
        if lparam == win32con.WM_LBUTTONUP:
            self.onClick()
        elif lparam == win32con.WM_LBUTTONDBLCLK:
            self.onDoubleClick()
        elif lparam ==  win32con.WM_RBUTTONUP:
            self.onRightClick()
        return 1

    def onCommand(self, hwnd, msg, wparam, lparam):
        nID = win32api.LOWORD(wparam)
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if nID == WM_TASKBARNOTIFY_MENUITEM_SHOW:
            win32gui.ShowWindow(hwnd, win32con.SW_SHOW|win32con.SW_MAXIMIZE)
        elif nID == WM_TASKBARNOTIFY_MENUITEM_HIDE:
            win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
        elif nID == WM_TASKBARNOTIFY_MENUITEM_EXIT:
            win32process.TerminateProcess(self.hProcess, 0)
            self.hide()
            sys.exit(0)
        return 1

    def onClick(self):
        v = ctypes.windll.user32.IsWindowVisible(ctypes.windll.kernel32.GetConsoleWindow())
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), {1:0,0:1}[v])

    def onDoubleClick(self):
        pass

    def onRightClick(self):
        menu = win32gui.CreatePopupMenu()
        win32gui.AppendMenu(menu, win32con.MF_STRING, WM_TASKBARNOTIFY_MENUITEM_SHOW, u'显示')
        win32gui.AppendMenu(menu, win32con.MF_STRING, WM_TASKBARNOTIFY_MENUITEM_HIDE, u'隐藏')
        win32gui.AppendMenu(menu, win32con.MF_STRING, WM_TASKBARNOTIFY_MENUITEM_EXIT, u'退出')
        pos = win32gui.GetCursorPos()
        win32gui.SetForegroundWindow(self.hwnd)
        win32gui.TrackPopupMenu(menu, win32con.TPM_LEFTALIGN, pos[0], pos[1], 0, self.hwnd, None)
        win32gui.PostMessage(self.hwnd, win32con.WM_NULL, 0, 0)

if __name__=='__main__':
    os.chdir(os.path.dirname(__file__))
    os.environ['PYTHONOPTIMIZE'] = 'x'
    t = Taskbar('py25.exe proxy.py', 'taskbar.exe', 'GoAgent Beta')
    win32gui.PumpMessages()