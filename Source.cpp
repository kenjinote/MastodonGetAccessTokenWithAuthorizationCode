#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "wininet")
#pragma comment(lib, "shlwapi")

#include <windows.h>
#include <shlwapi.h>
#include <wininet.h>
#include "json11.hpp"

#define ID_BUTTON 1000
#define ID_CODE 1001

#define URL_SCHEMEA "KenjiNoteMastodonClient"
#define URL_SCHEMEW L""URL_SCHEMEA

WCHAR szClassName[] = L"{26E639E3-13CB-493E-9887-F1FECA0E1BE2}"; // FindWindowで別のWindowがヒットしないようにクラス名にランダムな文字列を使う

BOOL GetStringFromJSON(LPCSTR lpszJson, LPCSTR lpszKey, LPSTR lpszValue) {
	std::string src(lpszJson);
	std::string err;
	json11::Json v = json11::Json::parse(src, err);
	if (err.size()) return FALSE;
	lpszValue[0] = 0;
	lstrcpyA(lpszValue, v[lpszKey].string_value().c_str());
	return lstrlenA(lpszValue) > 0;
}

LPSTR Post(LPCWSTR lpszServer, LPCWSTR lpszPath, LPCWSTR lpszHeader, LPBYTE lpbyData, int nSize) {
	LPSTR lpszReturn = 0;
	if (!lpszServer && !lpszServer[0]) goto END1;
	const HINTERNET hInternet = InternetOpenW(L"WinInet Test Program", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet) goto END1;
	const HINTERNET hHttpSession = InternetConnectW(hInternet, lpszServer, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hHttpSession) goto END2;
	const HINTERNET hHttpRequest = HttpOpenRequestW(hHttpSession, L"POST", lpszPath, NULL, 0, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
	if (!hHttpRequest) goto END3;
	if (HttpSendRequestW(hHttpRequest, lpszHeader, lstrlenW(lpszHeader), lpbyData, nSize) == FALSE) goto END4;
	{
		LPBYTE lpszByte = (LPBYTE)GlobalAlloc(GPTR, 1);
		DWORD dwRead, dwSize = 0;
		static BYTE szBuffer[1024 * 4];
		for (;;) {
			if (!InternetReadFile(hHttpRequest, szBuffer, (DWORD)sizeof(szBuffer), &dwRead) || !dwRead) break;
			LPBYTE lpTemp = (LPBYTE)GlobalReAlloc(lpszByte, (SIZE_T)(dwSize + dwRead + 1), GMEM_MOVEABLE);
			if (lpTemp == NULL) break;
			lpszByte = lpTemp;
			CopyMemory(lpszByte + dwSize, szBuffer, dwRead);
			dwSize += dwRead;
		}
		lpszByte[dwSize] = 0;
		lpszReturn = (LPSTR)lpszByte;
	}
END4:
	InternetCloseHandle(hHttpRequest);
END3:
	InternetCloseHandle(hHttpSession);
END2:
	InternetCloseHandle(hInternet);
END1:
	return lpszReturn;
}

BOOL GetClientIDAndClientSecret(LPCWSTR lpszServer, LPWSTR lpszClientID, LPWSTR lpszClientSecret) {
	BOOL bReturnValue = FALSE;
	CHAR szData[128];
	wsprintfA(szData, "client_name=TootApp2&redirect_uris=%s%%3A%%2F%%2Fa&scopes=write", URL_SCHEMEA);
	LPSTR lpszReturn = Post(lpszServer, L"/api/v1/apps", L"Content-Type: application/x-www-form-urlencoded", (LPBYTE)szData, lstrlenA(szData));
	if (lpszReturn) {
		CHAR szClientID[65];
		CHAR szClientSecret[65];
		bReturnValue = GetStringFromJSON(lpszReturn, "client_id", szClientID) & GetStringFromJSON(lpszReturn, "client_secret", szClientSecret);
		if (bReturnValue) {
			MultiByteToWideChar(CP_UTF8, 0, szClientID, -1, lpszClientID, 65);
			MultiByteToWideChar(CP_UTF8, 0, szClientSecret, -1, lpszClientSecret, 65);
		}
		else {
			CHAR szError[1024];
			WCHAR szErrorW[1024];
			if (GetStringFromJSON(lpszReturn, "error", szError))
			{
				MultiByteToWideChar(CP_UTF8, 0, szError, -1, szErrorW, _countof(szErrorW));
				MessageBoxW(0, szErrorW, 0, 0);
			}
		}
		GlobalFree(lpszReturn);
	}
	return bReturnValue;
}

BOOL GetAccessTokenByCode(LPCWSTR lpszServer, LPCWSTR lpszClientID, LPCWSTR lpszClientSecret, LPCWSTR lpszCode, LPWSTR lpszAccessToken) {
	BOOL bReturnValue = FALSE;
	CHAR szClientID[65];
	CHAR szClientSecret[65];
	CHAR szCode[65];
	WideCharToMultiByte(CP_UTF8, 0, lpszClientID, -1, szClientID, _countof(szClientID), 0, 0);
	WideCharToMultiByte(CP_UTF8, 0, lpszClientSecret, -1, szClientSecret, _countof(szClientSecret), 0, 0);
	WideCharToMultiByte(CP_UTF8, 0, lpszCode, -1, szCode, _countof(szCode), 0, 0);
	CHAR szData[1024];
	wsprintfA(szData, "scope=write&grant_type=authorization_code&redirect_uri=%s%%3A%%2F%%2Fa&client_id=%s&client_secret=%s&code=%s", URL_SCHEMEA, szClientID, szClientSecret, szCode);
	LPSTR lpszReturn = Post(lpszServer, L"/oauth/token", L"Content-Type: application/x-www-form-urlencoded", (LPBYTE)szData, lstrlenA(szData));
	if (lpszReturn) {
		CHAR szAccessToken[65];
		bReturnValue = GetStringFromJSON(lpszReturn, "access_token", szAccessToken);
		if (bReturnValue) {
			MultiByteToWideChar(CP_UTF8, 0, szAccessToken, -1, lpszAccessToken, 65);
		} else {
			CHAR szError[1024];
			WCHAR szErrorW[1024];
			if (GetStringFromJSON(lpszReturn, "error", szError)) {
				MultiByteToWideChar(CP_UTF8, 0, szError, -1, szErrorW, _countof(szErrorW));
				MessageBoxW(0, szErrorW, 0, 0);
			}
		}
		GlobalFree(lpszReturn);
	}
	return bReturnValue;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hButton, hEdit1, hEdit2, hEdit3, hEdit4, hEdit5;
	switch (msg)
	{
	case WM_CREATE:
		if (!ChangeWindowMessageFilterEx(hWnd, WM_COPYDATA, MSGFLT_ALLOW, NULL)) return -1;
		hEdit1 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton = CreateWindowW(L"BUTTON", L"authorization_codeでアクセストークンを取得", WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)ID_BUTTON, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit2 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit3 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit4 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit5 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		break;
	case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hWnd, &ps);
			TextOutW(hdc, 0, 15, L"Server:", 7);
			TextOutW(hdc, 0, 95, L"Client ID:", 10);
			TextOutW(hdc, 0, 135, L"Client Secret:", 14);
			TextOutW(hdc, 0, 175, L"Code:", 5);
			TextOutW(hdc, 0, 215, L"Access Token:", 13);
			EndPaint(hWnd, &ps);
		}
		break;
	case WM_SIZE:
		MoveWindow(hEdit1, 110, 10, LOWORD(lParam) - 120, 32, TRUE);
		MoveWindow(hButton, 10, 50, LOWORD(lParam) - 20, 32, TRUE);
		MoveWindow(hEdit2, 110, 90, LOWORD(lParam) - 120, 32, TRUE);
		MoveWindow(hEdit3, 110, 130, LOWORD(lParam) - 120, 32, TRUE);
		MoveWindow(hEdit4, 110, 170, LOWORD(lParam) - 120, 32, TRUE);
		MoveWindow(hEdit5, 110, 210, LOWORD(lParam) - 120, 32, TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == ID_BUTTON) {
			WCHAR szServer[256], szClientID[65], szClientSecret[65];
			GetWindowTextW(hEdit1, szServer, _countof(szServer));
			if (GetClientIDAndClientSecret(szServer, szClientID, szClientSecret)) {
				SetWindowTextW(hEdit2, szClientID);
				SetWindowTextW(hEdit3, szClientSecret);
				WCHAR szUrl[1024];
				wsprintfW(szUrl, L"https://%s/oauth/authorize?scope=write&client_id=%s&redirect_uri=%s%%3A%%2F%%2Fa&response_type=code", szServer, szClientID, URL_SCHEMEW);
				ShellExecuteW(hWnd, L"open", szUrl, 0, 0, SW_SHOW);
			}
		}
		break;
	case WM_COPYDATA:
		{
			PCOPYDATASTRUCT lpcopydata = (PCOPYDATASTRUCT)lParam;
			if (lpcopydata == 0 || lpcopydata->cbData != sizeof(WCHAR) * 65) return 0;
			SetWindowTextW(hEdit4, (LPCWSTR)lpcopydata->lpData);
			WCHAR szServer[256];
			GetWindowTextW(hEdit1, szServer, _countof(szServer));
			WCHAR szClientID[65];
			GetWindowTextW(hEdit2, szClientID, _countof(szClientID));
			WCHAR szClientSecret[65];
			GetWindowTextW(hEdit3, szClientSecret, _countof(szClientSecret));
			WCHAR szCode[65];
			GetWindowTextW(hEdit4, szCode, _countof(szCode));
			WCHAR szAccessToken[65];
			if (GetAccessTokenByCode(szServer, szClientID, szClientSecret, szCode, szAccessToken))
			{
				SetWindowTextW(hEdit5, szAccessToken);
			}
			SetForegroundWindow(hWnd);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPWSTR pCmdLine, int nCmdShow)
{
	{
		const HWND hWnd = FindWindowW(szClassName, NULL);
		if (hWnd) {
			int n;
			LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &n);
			if (n == 2) {
				LPWSTR p = argv[1];
				while (*p && *p != L'=') ++p;
				if (*p) {
					++p;
					COPYDATASTRUCT copydata = { 0 };
					copydata.cbData = sizeof(WCHAR) * (lstrlenW(p) + 1);
					copydata.lpData = p;
					SendMessageW(hWnd, WM_COPYDATA, (WPARAM)0, (LPARAM)&copydata);
				}
			}
			if (argv) LocalFree(argv);
			return 0;
		}
	}
	MSG msg;
	WNDCLASSW wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClassW(&wndclass);
	HWND hWnd = CreateWindowW(
		szClassName,
		L"Mastodon (authorization_codeでアクセストークンを取得)",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessageW(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	return (int)msg.wParam;
}
