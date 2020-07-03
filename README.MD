# CRZKD
Simply driver with IOCTL comunication method

Prepared to go with kdmapper https://github.com/TheCruZ/kdmapper-1803-2004

IOCTL function trampolines are at the end of the PAGE section of tcpip.sys driver, in the alignment

You should change areas where comments say "YOU MUST CHANGE THIS" for more undetectability

IOCTL name is \\\\.\\NsiLookup but you must change it


Example usage getting the pid and the base address of a process:

    const HANDLE driver = CreateFile(
        L"\\\\.\\NsiLookup",
        GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (driver == INVALID_HANDLE_VALUE) {
        MessageBox(NULL, L"Can't open", L"Error", 0);
        return GetLastError();
    }

    const wchar_t* n = L"explorer.exe";

    PidBaseResponse result = { 0 };
    PidBase cmd2 = { 0 };
    memcpy(cmd2.name, n, wcslen(n) * sizeof(wchar_t));
    cmd2.RetInfoPid = (uintptr_t)&result.pid;
    cmd2.RetInfoAddr = (uintptr_t)&result.baseAddr;

    if (!DeviceIoControl(driver, GET_PID_AND_BASE, &cmd2, sizeof(PidBase), NULL, NULL, NULL, NULL)) {
        MessageBox(NULL, L"Unknown", L"Error", 0);
        return GetLastError();
    }

    if (result.pid == 0) {
        MessageBox(NULL, L"No info received", L"Error", 0);
        return FALSE;
    }

Have fun ;)