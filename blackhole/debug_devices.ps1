# ============================================================================
# Debug Script - Enumerate Raw Input Devices
# Shows all keyboard and mouse devices detected by Windows
# ============================================================================

Write-Host ""
Write-Host "========================================"
Write-Host "  Raw Input Device Enumeration"
Write-Host "========================================"
Write-Host ""

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class RawInputDevices {
    [StructLayout(LayoutKind.Sequential)]
    public struct RAWINPUTDEVICELIST {
        public IntPtr hDevice;
        public uint dwType;
    }

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetRawInputDeviceList(
        [Out] RAWINPUTDEVICELIST[] pRawInputDeviceList,
        ref uint puiNumDevices,
        uint cbSize);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetRawInputDeviceInfo(
        IntPtr hDevice,
        uint uiCommand,
        IntPtr pData,
        ref uint pcbSize);

    public const uint RIDI_DEVICENAME = 0x20000007;
    public const uint RIM_TYPEMOUSE = 0;
    public const uint RIM_TYPEKEYBOARD = 1;
    public const uint RIM_TYPEHID = 2;

    public static List<string> EnumerateDevices() {
        List<string> devices = new List<string>();
        uint deviceCount = 0;
        uint structSize = (uint)Marshal.SizeOf(typeof(RAWINPUTDEVICELIST));

        // First call to get count
        GetRawInputDeviceList(null, ref deviceCount, structSize);

        if (deviceCount == 0) {
            return devices;
        }

        // Allocate array
        RAWINPUTDEVICELIST[] deviceList = new RAWINPUTDEVICELIST[deviceCount];
        GetRawInputDeviceList(deviceList, ref deviceCount, structSize);

        // Get device names
        for (int i = 0; i < deviceCount; i++) {
            uint size = 0;
            GetRawInputDeviceInfo(deviceList[i].hDevice, RIDI_DEVICENAME, IntPtr.Zero, ref size);

            if (size > 0) {
                IntPtr buffer = Marshal.AllocHGlobal((int)size * 2);
                GetRawInputDeviceInfo(deviceList[i].hDevice, RIDI_DEVICENAME, buffer, ref size);
                string deviceName = Marshal.PtrToStringUni(buffer);
                Marshal.FreeHGlobal(buffer);

                string deviceType = "UNKNOWN";
                if (deviceList[i].dwType == RIM_TYPEMOUSE) deviceType = "MOUSE";
                else if (deviceList[i].dwType == RIM_TYPEKEYBOARD) deviceType = "KEYBOARD";
                else if (deviceList[i].dwType == RIM_TYPEHID) deviceType = "HID";

                devices.Add(deviceType + "|" + deviceName);
            }
        }

        return devices;
    }
}
"@

try {
    $devices = [RawInputDevices]::EnumerateDevices()
    
    if ($devices.Count -eq 0) {
        Write-Host "No raw input devices found!" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit
    }

    Write-Host "Found $($devices.Count) raw input devices:"
    Write-Host ""
    
    $keyboards = @()
    $mice = @()
    $hids = @()
    
    foreach ($device in $devices) {
        $parts = $device -split '\|', 2
        $type = $parts[0]
        $name = $parts[1]
        
        if ($type -eq "KEYBOARD") {
            $keyboards += $name
        } elseif ($type -eq "MOUSE") {
            $mice += $name
        } else {
            $hids += $name
        }
    }
    
    Write-Host "KEYBOARDS ($($keyboards.Count)):" -ForegroundColor Cyan
    Write-Host "================================"
    foreach ($kb in $keyboards) {
        Write-Host "  $kb"
    }
    Write-Host ""
    
    Write-Host "MICE ($($mice.Count)):" -ForegroundColor Green
    Write-Host "================================"
    foreach ($mouse in $mice) {
        Write-Host "  $mouse"
    }
    Write-Host ""
    
    if ($hids.Count -gt 0) {
        Write-Host "OTHER HID DEVICES ($($hids.Count)):" -ForegroundColor Yellow
        Write-Host "================================"
        foreach ($hid in $hids) {
            Write-Host "  $hid"
        }
        Write-Host ""
    }
    
    Write-Host "========================================"
    Write-Host "  Analysis"
    Write-Host "========================================"
    Write-Host ""
    
    # Check for common hypervisor identifiers
    $identifiers = @("QEMU", "VMware", "VirtualBox", "Hyper-V", "Virtual", "HID")
    $found = @{}
    
    foreach ($id in $identifiers) {
        $matches = $devices | Where-Object { $_ -like "*$id*" }
        if ($matches.Count -gt 0) {
            $found[$id] = $matches.Count
        }
    }
    
    if ($found.Count -gt 0) {
        Write-Host "Detected hypervisor identifiers:" -ForegroundColor Green
        foreach ($key in $found.Keys) {
            Write-Host "  - '$key' found in $($found[$key]) device(s)"
        }
        Write-Host ""
        Write-Host "Recommended HYPERVISOR_IDENTIFIERS:" -ForegroundColor Yellow
        Write-Host "  HYPERVISOR_IDENTIFIERS = ["
        foreach ($key in $found.Keys) {
            Write-Host "      `"$key`","
        }
        Write-Host "  ]"
    } else {
        Write-Host "WARNING: No common hypervisor identifiers found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "You may need to manually add identifiers from the device names above."
        Write-Host "Look for unique strings in the keyboard/mouse device names."
    }
    
    Write-Host ""
    
} catch {
    Write-Host "ERROR: Failed to enumerate devices" -ForegroundColor Red
    Write-Host $_.Exception.Message
}

Write-Host ""
Read-Host "Press Enter to exit"

