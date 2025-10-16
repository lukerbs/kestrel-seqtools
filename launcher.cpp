/*
 * Kestrel SeqTools - IExpress Launcher
 * 
 * This tiny C++ launcher serves as a GUI-subsystem wrapper to eliminate
 * the console flash when launching the PyInstaller executable.
 * 
 * Key behaviors:
 * - Runs as a GUI app (no console creation)
 * - Checks for .dev_mode marker file
 * - Launches passwords.txt_main.exe with CREATE_NO_WINDOW (production) or visible console (dev)
 * - Exits immediately after spawning the main app
 */

#include <windows.h>
#include <string>
#include <vector>

/**
 * Get the full path to this launcher executable
 */
std::wstring GetExecutablePath() {
    std::vector<wchar_t> pathBuf(MAX_PATH);
    DWORD copied = 0;
    DWORD size = static_cast<DWORD>(pathBuf.size());
    
    while (true) {
        copied = GetModuleFileNameW(NULL, pathBuf.data(), size);
        if (copied < size) {
            break;
        }
        size *= 2;
        pathBuf.resize(size);
    }
    
    pathBuf.resize(copied);
    return std::wstring(pathBuf.begin(), pathBuf.end());
}

/**
 * Check if .dev_mode marker file exists in the same directory as this executable
 */
bool IsDevMode() {
    std::wstring launcherPath = GetExecutablePath();
    size_t lastSlash = launcherPath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) {
        return false;
    }
    
    std::wstring directory = launcherPath.substr(0, lastSlash);
    std::wstring devModeFile = directory + L"\\.dev_mode";
    
    DWORD fileAttr = GetFileAttributesW(devModeFile.c_str());
    return (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
}

/**
 * WinMain entry point - GUI subsystem, no console
 */
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    // Get the directory containing this launcher
    std::wstring launcherPath = GetExecutablePath();
    size_t lastSlash = launcherPath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) {
        return 1; // Failed to parse path
    }
    
    std::wstring directory = launcherPath.substr(0, lastSlash);
    std::wstring mainAppPath = directory + L"\\passwords.txt_main.exe";
    
    // Check if we're in dev mode
    bool devMode = IsDevMode();
    
    // Prepare process startup information
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    
    // Build command line (include original args if any)
    std::wstring cmdLine = L"\"" + mainAppPath + L"\"";
    if (lpCmdLine && wcslen(lpCmdLine) > 0) {
        cmdLine += L" ";
        cmdLine += lpCmdLine;
    }
    
    // Convert to mutable buffer (CreateProcessW requires non-const)
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);
    
    // Determine creation flags based on dev mode
    DWORD creationFlags = 0;
    if (!devMode) {
        // Production mode: hide console completely
        creationFlags = CREATE_NO_WINDOW;
    }
    // Dev mode: use default flags (console will be visible if main app creates one)
    
    // Launch the main application
    BOOL success = CreateProcessW(
        NULL,                   // Application name (use command line instead)
        cmdBuf.data(),          // Command line
        NULL,                   // Process security attributes
        NULL,                   // Thread security attributes
        FALSE,                  // Inherit handles
        creationFlags,          // Creation flags
        NULL,                   // Environment
        NULL,                   // Current directory
        &si,                    // Startup info
        &pi                     // Process information
    );
    
    if (success) {
        // Close handles immediately - we don't need to wait
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }
    
    // Launch failed - in production mode, fail silently
    // In dev mode, this would be visible if a console was created
    return 1;
}

