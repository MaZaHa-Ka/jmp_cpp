#pragma once
#include <cstdarg>
#include <xstring>
#include <WinUser.h>
#include <processthreadsapi.h>

static void RaiseError(const char* fmt, ...)
{
	char buf[2048];
	va_list args;
	va_start(args, fmt);
	vsprintf_s(buf, fmt, args);
	va_end(args);

	MessageBoxA(HWND_DESKTOP, buf, "Fatal Error", MB_SYSTEMMODAL | MB_ICONWARNING);
	//ExitProcess(EXIT_SUCCESS);
}
static void Mbox(const char* msg, const char* title)
{
	//char buf[2048];
	//va_list args;
	//va_start(args, msg);
	//vsprintf_s(buf, msg, args);
	//va_end(args);

	MessageBoxA(HWND_DESKTOP, msg, title, MB_SYSTEMMODAL | MB_ICONWARNING);
}
static void Mbox(std::string msg, std::string title)
{
	MessageBoxA(HWND_DESKTOP, msg.c_str(), title.c_str(), MB_SYSTEMMODAL | MB_ICONWARNING);
}

static void EXIT()
{
	ExitProcess(EXIT_FAILURE);
}

#ifdef DEBUG
#define XM_Error(fmt, ...) \
	RaiseError(__FUNCTION__ ": " fmt, __VA_ARGS__)
#else
#define XM_Error(...) \
	ExitProcess(EXIT_FAILURE)
#endif