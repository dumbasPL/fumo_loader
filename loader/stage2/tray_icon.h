#pragma once
#include <Windows.h>
#include <string>

class TrayIcon {
private:
    std::wstring name = L"";
    HINSTANCE hInstance = NULL;
    std::wstring window_class_name = L"";
    HWND hwnd = NULL;
    UINT uID = 1;
    HANDLE hCancelEvent = NULL;
public:
    TrayIcon(std::wstring name);
    ~TrayIcon();
    void create_icon(HWND hwnd);
    void destroy_icon();
    void set_icon_message(LPCWSTR lpMessage);
    void clear_notification();
    void send_notification(LPCWSTR lpMessage);
    void cancel_wait();
    void destroy();
    
    DWORD wait_for_object(HANDLE hHandle, DWORD dwMilliseconds, LPCWSTR lpMessage);
};
