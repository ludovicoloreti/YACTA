/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "pe"

rule DebuggerCheck__PEB : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="NtGlobalFlags"
	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="QueryInformationProcess"
	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
}

rule DebuggerHiding__Thread : AntiDebug {
	meta:
	    Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="DebugActiveProcess"
	condition:
		any of them
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerTiming__PerformanceCounter : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="QueryPerformanceCounter"
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerTiming__Ticks : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="GetTickCount"
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerOutput__String : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="OutputDebugString"
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerException__UnhandledFilter : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetUnhandledExceptionFilter"
	condition:
		any of them
}
*/

rule DebuggerException__ConsoleCtrl : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="GenerateConsoleCtrlEvent"
	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

rule ThreadControl__Context : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="__invoke__watson"
	condition:
		any of them
}

rule SEH__v3 : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}

rule SEH__v4 : AntiDebug {
    // VS 8.0+
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"
	condition:
		any of them
}

rule SEH__vba : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

rule SEH__vectored : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__RDTSC : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {0F 31}
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__CPUID : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {0F A2}
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__SEH_Saves : AntiDebug {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {64 ff 35 00 00 00 00}
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__SEH_Inits : AntiDebug {
	meta:
		Author = "naxonez"
        description = "Tries to detect virtualized environments"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {64 89 25 00 00 00 00}
	condition:
		any of them
}
*/

rule VM_Generic_Detection : AntiVM
{
    meta:
        description = "Tries to detect virtualized environments"
    strings:
        $a0 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $a1 = "HARDWARE\\Description\\System" nocase wide ascii
        $a2 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase wide ascii
        $a3 = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
        $redpill = { 0F 01 0D 00 00 00 00 C3 } // Copied from the Cuckoo project

        // CLSIDs used to detect if speakers are present. Hoping this will not cause false positives.
        $teslacrypt1 = { D1 29 06 E3 E5 27 CE 11 87 5D 00 60 8C B7 80 66 } // CLSID_AudioRender
        $teslacrypt2 = { B3 EB 36 E4 4F 52 CE 11 9F 53 00 20 AF 0B A7 70 } // CLSID_FilterGraph

    condition:
        any of ($a*) or $redpill or all of ($teslacrypt*)
}

rule VMWare_Detection : AntiVM
{
    meta:
        description = "Looks for VMWare presence"
        author = "Cuckoo project"

    strings:
        $a0 = "VMXh"
        $a1 = "vmware" nocase wide ascii
        $vmware4 = "hgfs.sys" nocase wide ascii
        $vmware5 = "mhgfs.sys" nocase wide ascii
        $vmware6 = "prleth.sys" nocase wide ascii
        $vmware7 = "prlfs.sys" nocase wide ascii
        $vmware8 = "prlmouse.sys" nocase wide ascii
        $vmware9 = "prlvideo.sys" nocase wide ascii
        $vmware10 = "prl_pv32.sys" nocase wide ascii
        $vmware11 = "vpc-s3.sys" nocase wide ascii
        $vmware12 = "vmsrvc.sys" nocase wide ascii
        $vmware13 = "vmx86.sys" nocase wide ascii
        $vmware14 = "vmnet.sys" nocase wide ascii
        $vmware15 = "vmicheartbeat" nocase wide ascii
        $vmware16 = "vmicvss" nocase wide ascii
        $vmware17 = "vmicshutdown" nocase wide ascii
        $vmware18 = "vmicexchange" nocase wide ascii
        $vmware19 = "vmdebug" nocase wide ascii
        $vmware20 = "vmmouse" nocase wide ascii
        $vmware21 = "vmtools" nocase wide ascii
        $vmware22 = "VMMEMCTL" nocase wide ascii
        $vmware23 = "vmx86" nocase wide ascii

        // VMware MAC addresses
        $vmware_mac_1a = "00-05-69" wide ascii
        $vmware_mac_1b = "00:05:69" wide ascii
        $vmware_mac_1c = "000569" wide ascii
        $vmware_mac_2a = "00-50-56" wide ascii
        $vmware_mac_2b = "00:50:56" wide ascii
        $vmware_mac_2c = "005056" wide ascii
        $vmware_mac_3a = "00-0C-29" nocase wide ascii
        $vmware_mac_3b = "00:0C:29" nocase wide ascii
        $vmware_mac_3c = "000C29" nocase wide ascii
        $vmware_mac_4a = "00-1C-14" nocase wide ascii
        $vmware_mac_4b = "00:1C:14" nocase wide ascii
        $vmware_mac_4c = "001C14" nocase wide ascii

        // PCI Vendor IDs, from Hacking Team's leak
        $virtualbox_vid_1 = "VEN_15ad" nocase wide ascii

    condition:
        any of them
}

rule Sandboxie_Detection : AntiVM
{
    meta:
        description = "Looks for Sandboxie presence"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $sbie = "SbieDll.dll" nocase wide ascii
        $buster = /LOG_API(_VERBOSE)?.DLL/ nocase wide ascii
        $sbie_process_1 = "SbieSvc.exe" nocase wide ascii
        $sbie_process_2 = "SbieCtrl.exe" nocase wide ascii
        $sbie_process_3 = "SandboxieRpcSs.exe" nocase wide ascii
        $sbie_process_4 = "SandboxieDcomLaunch.exe" nocase wide ascii
        $sbie_process_5 = "SandboxieCrypto.exe" nocase wide ascii
        $sbie_process_6 = "SandboxieBITS.exe" nocase wide ascii
        $sbie_process_7 = "SandboxieWUAU.exe" nocase wide ascii

    condition:
        any of them
}

rule VirtualPC_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualPC presence"
        author = "Cuckoo project"

    strings:
        $a0 = {0F 3F 07 0B }
        $virtualpc1 = "vpcbus" nocase wide ascii
        $virtualpc2 = "vpc-s3" nocase wide ascii
        $virtualpc3 = "vpcuhub" nocase wide ascii
        $virtualpc4 = "msvmmouf" nocase wide ascii

    condition:
        any of them
}

rule VirtualBox_Detection : AntiVM
{
    meta:
        description = "Looks for VirtualBox presence"
        author = "Cuckoo project"
    strings:
        $virtualbox1 = "VBoxHook.dll" nocase wide ascii
        $virtualbox2 = "VBoxService" nocase wide ascii
        $virtualbox3 = "VBoxTray" nocase wide ascii
        $virtualbox4 = "VBoxMouse" nocase wide ascii
        $virtualbox5 = "VBoxGuest" nocase wide ascii
        $virtualbox6 = "VBoxSF" nocase wide ascii
        $virtualbox7 = "VBoxGuestAdditions" nocase wide ascii
        $virtualbox8 = "VBOX HARDDISK" nocase wide ascii
        $virtualbox9 = "vboxservice" nocase wide ascii
        $virtualbox10 = "vboxtray" nocase wide ascii

        // MAC addresses
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

        // PCI Vendor IDs, from Hacking Team's leak
        $virtualbox_vid_1 = "VEN_80EE" nocase wide ascii

        // Registry keys
        $virtualbox_reg_1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
        $virtualbox_reg_2 = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\VBOX__/ nocase wide ascii

        // Other
        $virtualbox_files = /C:\\Windows\\System32\\drivers\\vbox.{15}\.(sys|dll)/ nocase wide ascii
        $virtualbox_services = "System\\ControlSet001\\Services\\VBox[A-Za-z]+" nocase wide ascii
        $virtualbox_pipe = /\\\\.\\pipe\\(VBoxTrayIPC|VBoxMiniRdDN)/ nocase wide ascii
        $virtualbox_window = /VBoxTrayToolWnd(Class)?/ nocase wide ascii
    condition:
        any of them
}

rule Parallels_Detection : AntiVM
{
    meta:
        description = "Looks for Parallels presence"
    strings:
        $a0 = "magi"
        $a1 = "c!nu"
        $a2 = "mber"

        // PCI Vendor IDs, from Hacking Team's leak
        $parallels_vid_1 = "VEN_80EE" nocase wide ascii
    condition:
        all of them
}

rule Qemu_Detection : AntiVM
{
    meta:
        description = "Looks for Qemu presence"
    strings:
        $a0 = "qemu" nocase wide ascii
    condition:
        any of them
}

rule Check_Dlls : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for common sandbox dlls"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$dll1 = "sbiedll.dll" wide nocase ascii fullword
		$dll2 = "dbghelp.dll" wide nocase ascii fullword
		$dll3 = "api_log.dll" wide nocase ascii fullword
		$dll4 = "dir_watch.dll" wide nocase ascii fullword
		$dll5 = "pstorec.dll" wide nocase ascii fullword
		$dll6 = "vmcheck.dll" wide nocase ascii fullword
		$dll7 = "wpespy.dll" wide nocase ascii fullword
	condition:
		2 of them
}

rule Check_Qemu_Description : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for QEMU systembiosversion key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "QEMU" wide nocase ascii
	condition:
		all of them
}

rule Check_Qemu_DeviceMap : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for Qemu reg keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$value = "Identifier" nocase wide ascii
		$data = "QEMU" wide nocase ascii
	condition:
		all of them
}

rule Check_VBox_Description : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox description reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "VBOX" nocase wide ascii
	condition:
		all of them
}
rule Check_VBox_DeviceMap : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox registry keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$value = "Identifier" nocase wide ascii
		$data = "VBOX" nocase wide ascii
	condition:
		all of them
}
rule Check_VBox_Guest_Additions : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of the guest additions registry key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii nocase
	condition:
		any of them
}
rule Check_VBox_VideoDrivers : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for reg keys of Vbox video drivers"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "VideoBiosVersion" wide nocase ascii
		$data = "VIRTUALBOX" nocase wide ascii
	condition:
		all of them
}
rule Check_VMWare_DeviceMap : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmWare Registry Keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
		$value = "Identifier" wide nocase ascii
		$data = "VMware" wide nocase ascii
	condition:
		all of them
}
rule Check_VmTools : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmTools reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$ ="SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
	condition:
		any of them
}
rule Check_Wine : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of Wine"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$ ="wine_get_unix_file_name"
	condition:
		any of them
}

rule vmdetect : AntiVM
{
    meta:
        author = "nex"
        description = "Possibly employs anti-virtualization techniques"

    strings:
        // Binary tricks
        $vmware = {56 4D 58 68}
        $virtualpc = {0F 3F 07 0B}
        $ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        $vmcheckdll = {45 C7 00 01}
        $redpill = {0F 01 0D 00 00 00 00 C3}

        // Random strings
        $vmware1 = "VMXh"
        $vmware2 = "Ven_VMware_" nocase
        $vmware3 = "Prod_VMware_Virtual_" nocase
        $vmware4 = "hgfs.sys" nocase
        $vmware5 = "mhgfs.sys" nocase
        $vmware6 = "prleth.sys" nocase
        $vmware7 = "prlfs.sys" nocase
        $vmware8 = "prlmouse.sys" nocase
        $vmware9 = "prlvideo.sys" nocase
        $vmware10 = "prl_pv32.sys" nocase
        $vmware11 = "vpc-s3.sys" nocase
        $vmware12 = "vmsrvc.sys" nocase
        $vmware13 = "vmx86.sys" nocase
        $vmware14 = "vmnet.sys" nocase
        $vmware15 = "vmicheartbeat" nocase
        $vmware16 = "vmicvss" nocase
        $vmware17 = "vmicshutdown" nocase
        $vmware18 = "vmicexchange" nocase
        $vmware19 = "vmdebug" nocase
        $vmware20 = "vmmouse" nocase
        $vmware21 = "vmtools" nocase
        $vmware22 = "VMMEMCTL" nocase
        $vmware23 = "vmx86" nocase
        $vmware24 = "vmware" nocase
        $virtualpc1 = "vpcbus" nocase
        $virtualpc2 = "vpc-s3" nocase
        $virtualpc3 = "vpcuhub" nocase
        $virtualpc4 = "msvmmouf" nocase
        $xen1 = "xenevtchn" nocase
        $xen2 = "xennet" nocase
        $xen3 = "xennet6" nocase
        $xen4 = "xensvc" nocase
        $xen5 = "xenvdb" nocase
        $xen6 = "XenVMM" nocase
        $virtualbox1 = "VBoxHook.dll" nocase
        $virtualbox2 = "VBoxService" nocase
        $virtualbox3 = "VBoxTray" nocase
        $virtualbox4 = "VBoxMouse" nocase
        $virtualbox5 = "VBoxGuest" nocase
        $virtualbox6 = "VBoxSF" nocase
        $virtualbox7 = "VBoxGuestAdditions" nocase
        $virtualbox8 = "VBOX HARDDISK"  nocase

        // MAC addresses
        $vmware_mac_1a = "00-05-69"
        $vmware_mac_1b = "00:05:69"
        $vmware_mac_1c = "000569"
        $vmware_mac_2a = "00-50-56"
        $vmware_mac_2b = "00:50:56"
        $vmware_mac_2c = "005056"
        $vmware_mac_3a = "00-0C-29" nocase
        $vmware_mac_3b = "00:0C:29" nocase
        $vmware_mac_3c = "000C29" nocase
        $vmware_mac_4a = "00-1C-14" nocase
        $vmware_mac_4b = "00:1C:14" nocase
        $vmware_mac_4c = "001C14" nocase
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

    condition:
        any of them
}

rule Check_Debugger : AntiDebug
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	condition:
		pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and
		pe.imports("kernel32.dll","IsDebuggerPresent")
}

rule Check_DriveSize : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO
	condition:
		pe.imports("kernel32.dll","CreateFileA") and
		pe.imports("kernel32.dll","DeviceIoControl") and
		$dwIoControlCode and
		$physicaldrive
}

rule Check_FilePaths : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for filepaths containing popular sandbox names"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$path1 = "SANDBOX" wide ascii
		$path2 = "\\SAMPLE" wide ascii
		$path3 = "\\VIRUS" wide ascii
	condition:
		all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA")
}

rule Check_UserNames : AntiVM
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for malware checking for common sandbox usernames"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$user1 = "MALTEST" wide ascii
		$user2 = "TEQUILABOOMBOOM" wide ascii
		$user3 = "SANDBOX" wide ascii
		$user4 = "VIRUS" wide ascii
		$user5 = "MALWARE" wide ascii
	condition:
		all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}


rule Check_OutputDebugStringA_iat : AntiDebug
{

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"

	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule Check_unhandledExceptionFiler_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if UnhandledExceptionFilter is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#UnhandledExceptionFilter"

	condition:
		pe.imports("kernel32.dll","UnhandledExceptionFilter")
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule check_RaiseException_iat : AntiDebug{

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if RaiseException is imported"
		Date = "20/04/2015"
		Reference = "http://waleedassar.blogspot.com.es/2012/11/ollydbg-raiseexception-bug.html"

	condition:
		pe.imports("kernel32.dll","RaiseException")
}
*/

rule Check_FindWindowA_iat : AntiDebug{

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if FindWindowA() is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

	strings:
		$ollydbg = "OLLYDBG"
		$windbg = "WinDbgFrameClass"

	condition:
		pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}

rule DebuggerCheck__MemoryWorkingSet : AntiDebug {
	meta:
		author = "Fernando Mercês"
		date = "2015-06"
		description = "Anti-debug process memory working set size check"
		reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

	condition:
		pe.imports("kernel32.dll", "K32GetProcessMemoryInfo") and
		pe.imports("kernel32.dll", "GetCurrentProcess")
}

rule WMI_VM_Detect : AntiVM
{
    meta:

        version = 2
        threat = "Using WMI to detect virtual machines via querying video card information"
        behaviour_class = "Evasion"
        author = "Joe Giron"
        date = "2015-09-25"
        description = "Detection of Virtual Appliances through the use of WMI for use of evasion."

		strings:

		$selstr 	= "SELECT Description FROM Win32_VideoController" nocase ascii wide
		$selstr2 	= "SELECT * FROM Win32_VideoController" nocase ascii wide
		$vm1 		= "virtualbox graphics adapter" nocase ascii wide
		$vm2 		= "vmware svga ii" nocase ascii wide
		$vm3 		= "vm additions s3 trio32/64" nocase ascii wide
		$vm4 		= "parallel" nocase ascii wide
		$vm5 		= "remotefx" nocase ascii wide
		$vm6 		= "cirrus logic" nocase ascii wide
		$vm7 		= "matrox" nocase ascii wide

		condition:
		any of ($selstr*) and any of ($vm*)


}

/*
rule anti_dbg : AntiDebug {
    meta:
        author = "x0r"
        description = "Checks if being debugged"
	version = "0.2"
    strings:
    	$d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent"
        $c2 = "IsDebuggerPresent"
        $c3 = "OutputDebugString"
        $c4 = "ContinueDebugEvent"
        $c5 = "DebugActiveProcess"
    condition:
        $d1 and 1 of ($c*)
}
*/

rule anti_dbgtools : AntiDebug {
    meta:
        author = "x0r"
        description = "Checks for the presence of known debug tools"
	version = "0.1"
    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE"
        $c12 = "\\\\.\\SICE"
        $c13 = "\\\\.\\Syser"
        $c14 = "\\\\.\\SyserBoot"
        $c15 = "\\\\.\\SyserDbgMsg"
    condition:
        any of them
}

rule antisb_joesanbox : AntiVM {
     meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Joe Sandbox"
	version = "0.1"
    strings:
	$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
	$c1 = "RegQueryValue"
	$s1 = "55274-640-2673064-23950"
    condition:
        all of them
}

rule antisb_anubis : AntiVM {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Anubis"
	version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue"
        $s1 = "76487-337-8429955-22614"
        $s2 = "76487-640-1457236-23837"
    condition:
        $p1 and $c1 and 1 of ($s*)
}

rule antisb_threatExpert : AntiVM {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for ThreatExpert"
	version = "0.1"
    strings:
        $f1 = "dbghelp.dll" nocase
    condition:
        all of them
}

rule antisb_sandboxie : AntiVM {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Sandboxie"
	version = "0.1"
    strings:
        $f1 = "SbieDLL.dll" nocase
    condition:
        all of them
}

rule antisb_cwsandbox : AntiVM {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for CWSandbox"
	version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $s1 = "76487-644-3177037-23510"
    condition:
        all of them
}

rule antivm_virtualbox : AntiVM {
    meta:
        author = "x0r"
        description = "AntiVM checks for VirtualBox"
	version = "0.1"
    strings:
        $s1 = "VBoxService.exe" nocase
    condition:
        any of them
}

rule antivm_vmware : AntiVM {
    meta:
        author = "x0r"
        description = "AntiVM checks for VMWare"
	version = "0.1"
    strings:
        $s1 = "vmware.exe" nocase
        $s2 = "vmware-authd.exe" nocase
        $s3 = "vmware-hostd.exe" nocase
        $s4 = "vmware-tray.exe" nocase
        $s5 = "vmware-vmx.exe" nocase
        $s6 = "vmnetdhcp.exe" nocase
        $s7 = "vpxclient.exe" nocase
    	$s8 = { b868584d56bb00000000b90a000000ba58560000ed }
    condition:
        any of them
}

rule antivm_bios : AntiVM{
    meta:
        author = "x0r"
        description = "AntiVM checks for Bios version"
	version = "0.2"
    strings:
        $p1 = "HARDWARE\\DESCRIPTION\\System" nocase
        $p2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" nocase
        $c1 = "RegQueryValue"
        $r1 = "SystemBiosVersion"
        $r2 = "VideoBiosVersion"
        $r3 = "SystemManufacturer"
    condition:
        1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}

rule disable_antivirus : DisableWindowsSecurity {
    meta:
        author = "x0r"
        description = "Disable AntiVirus"
	version = "0.2"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
        $c1 = "RegSetValue"
        $r1 = "AntiVirusDisableNotify"
        $r2 = "DontReportInfectionInformation"
        $r3 = "DisableAntiSpyware"
        $r4 = "RunInvalidSignatures"
        $r5 = "AntiVirusOverride"
        $r6 = "CheckExeSignatures"
        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase
    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule disable_uax : DisableWindowsSecurity  {
    meta:
        author = "x0r"
        description = "Disable User Access Control"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule disable_firewall : DisableWindowsSecurity {
    meta:
        author = "x0r"
        description = "Disable Firewall"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue"
        $r1 = "FirewallPolicy"
        $r2 = "EnableFirewall"
        $r3 = "FirewallDisableNotify"
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry : DisableWindowsSecurity {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue"
        $r1 = "DisableRegistryTools"
        $r2 = "DisableRegedit"
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_dep : DisableWindowsSecurity {
    meta:
        author = "x0r"
        description = "Bypass DEP"
	version = "0.1"
    strings:
        $c1 = "EnableExecuteProtectionSupport"
        $c2 = "NtSetInformationProcess"
        $c3 = "VirtualProctectEx"
        $c4 = "SetProcessDEPPolicy"
        $c5 = "ZwProtectVirtualMemory"
    condition:
        any of them
}

rule disable_taskmanager : DisableWindowsSecurity {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr"
    condition:
        1 of ($p*) and 1 of ($r*)
}

rule create_process {
    meta:
        author = "x0r"
        description = "Create a new process"
	version = "0.2"
    strings:
        $f1 = "Shell32.dll" nocase
        $f2 = "Kernel32.dll" nocase
        $c1 = "ShellExecute"
        $c2 = "WinExec"
        $c3 = "CreateProcess"
        $c4 = "CreateThread"
    condition:
        ($f1 and $c1 ) or $f2 and ($c2 or $c3 or $c4)
}
rule persistence {
    meta:
        author = "x0r"
        description = "Install itself for autorun at Windows startup"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $p2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $p3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $p4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        $p5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $p6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase
        $p7 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" nocase
        $p8 = "SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Windows" nocase
        $p9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" nocase
        $p10 = "comfile\\shell\\open\\command" nocase
        $p11 = "piffile\\shell\\open\\command" nocase
        $p12 = "exefile\\shell\\open\\command" nocase
        $p13 = "txtfile\\shell\\open\\command" nocase
	$p14 = "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        $f1 = "win.ini" nocase
        $f2 = "system.ini" nocase
        $f3 = "Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

rule hijack_network : ModifySystem {
    meta:
        author = "x0r"
        description = "Hijack network configuration"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Classes\\PROTOCOLS\\Handler" nocase
        $p2 = "SOFTWARE\\Classes\\PROTOCOLS\\Filter" nocase
        $p3 = "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer" nocase
        $p4 = "software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" nocase
        $f1 = "drivers\\etc\\hosts" nocase
    condition:
        any of them
}

rule create_service : ModifySystem {
    meta:
        author = "x0r"
        description = "Create a windows service"
	version = "0.2"
    strings:
	$f1 = "Advapi32.dll" nocase
        $c1 = "CreateService"
        $c2 = "ControlService"
        $c3 = "StartService"
        $c4 = "QueryServiceStatus"
    condition:
        all of them
}

rule create_com_service : ModifySystem {
    meta:
        author = "x0r"
        description = "Create a COM server"
	version = "0.1"
    strings:
        $c1 = "DllCanUnloadNow" nocase
        $c2 = "DllGetClassObject"
        $c3 = "DllInstall"
        $c4 = "DllRegisterServer"
        $c5 = "DllUnregisterServer"
    condition:
        all of them
}

rule network_udp_sock : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over UDP network"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
	$f2 = "System.Net" nocase
        $f3 = "wsock32.dll" nocase
        $c0 = "WSAStartup"
        $c1 = "sendto"
        $c2 = "recvfrom"
        $c3 = "WSASendTo"
        $c4 = "WSARecvFrom"
        $c5 = "UdpClient"
    condition:
        (($f1 or $f3) and 2 of ($c*)) or ($f2 and $c5)
}

rule network_tcp_listen : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Listen for incoming communication"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Mswsock.dll" nocase
	    $f3 = "System.Net" nocase
        $f4 = "wsock32.dll" nocase
        $c1 = "bind"
        $c2 = "accept"
        $c3 = "GetAcceptExSockaddrs"
        $c4 = "AcceptEx"
        $c5 = "WSAStartup"
        $c6 = "WSAAccept"
        $c7 = "WSASocket"
        $c8 = "TcpListener"
        $c9 = "AcceptTcpClient"
        $c10 = "listen"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dyndns : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications dyndns network"
	version = "0.1"
    strings:
	$s1 =".no-ip.org"
        $s2 =".publicvm.com"
        $s3 =".linkpc.net"
        $s4 =".dynu.com"
        $s5 =".dynu.net"
        $s6 =".afraid.org"
        $s7 =".chickenkiller.com"
        $s8 =".crabdance.com"
        $s9 =".ignorelist.com"
        $s10 =".jumpingcrab.com"
        $s11 =".moo.com"
        $s12 =".strangled.com"
        $s13 =".twillightparadox.com"
        $s14 =".us.to"
        $s15 =".strangled.net"
        $s16 =".info.tm"
        $s17 =".homenet.org"
        $s18 =".biz.tm"
        $s19 =".continent.kz"
        $s20 =".ax.lt"
        $s21 =".system-ns.com"
        $s22 =".adultdns.com"
        $s23 =".craftx.biz"
        $s24 =".ddns01.com"
        $s25 =".dns53.biz"
        $s26 =".dnsapi.info"
        $s27 =".dnsd.info"
        $s28 =".dnsdynamic.com"
        $s29 =".dnsdynamic.net"
        $s30 =".dnsget.org"
        $s31 =".fe100.net"
        $s32 =".flashserv.net"
        $s33 =".ftp21.net"
    condition:
        any of them
}

rule network_toredo : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over Toredo network"
	version = "0.1"
    strings:
	$f1 = "FirewallAPI.dll" nocase
        $p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase
    condition:
        all of them
}

rule network_smtp_dotNet : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
    condition:
        all of them
}

rule network_smtp_vb : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$c1 = "CDO.Message" nocase
        $c2 = "cdoSMTPServer" nocase
        $c3 = "cdoSendUsingMethod" nocase
        $c4 = "cdoex.dll" nocase
        $c5 = "/cdo/configuration/smtpserver" nocase
    condition:
        any of them
}

rule network_p2p_win : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over P2P network"
	version = "0.1"
    strings:
     	$c1 = "PeerCollabExportContact"
     	$c2 = "PeerCollabGetApplicationRegistrationInfo"
     	$c3 = "PeerCollabGetEndpointName"
     	$c4 = "PeerCollabGetEventData"
     	$c5 = "PeerCollabGetInvitationResponse"
     	$c6 = "PeerCollabGetPresenceInfo"
     	$c7 = "PeerCollabGetSigninOptions"
     	$c8 = "PeerCollabInviteContact"
     	$c9 = "PeerCollabInviteEndpoint"
     	$c10 = "PeerCollabParseContact"
     	$c11 = "PeerCollabQueryContactData"
     	$c12 = "PeerCollabRefreshEndpointData"
     	$c13 = "PeerCollabRegisterApplication"
     	$c14 = "PeerCollabRegisterEvent"
     	$c15 = "PeerCollabSetEndpointName"
     	$c16 = "PeerCollabSetObject"
     	$c17 = "PeerCollabSetPresenceInfo"
     	$c18 = "PeerCollabSignout"
     	$c19 = "PeerCollabUnregisterApplication"
     	$c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
}

rule network_tor : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
	version = "0.1"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}
rule network_irc : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over IRC network"
	version = "0.1"
    strings:
        $s1 = "NICK"
        $s2 = "PING"
        $s3 = "JOIN"
        $s4 = "USER"
        $s5 = "PRIVMSG"
    condition:
        all of them
}

rule network_http : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over HTTP"
	version = "0.1"
    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect"
        $c2 = "InternetOpen"
        $c3 = "InternetOpenUrl"
        $c4 = "InternetReadFile"
        $c5 = "InternetWriteFile"
        $c6 = "HttpOpenRequest"
        $c7 = "HttpSendRequest"
        $c8 = "IdHTTPHeaderInfo"
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
}

rule network_dropper : NetworkCommunication {
    meta:
        author = "x0r"
        description = "File downloader/dropper"
	version = "0.1"
    strings:
        $f1 = "urlmon.dll" nocase
        $c1 = "URLDownloadToFile"
        $c2 = "URLDownloadToCacheFile"
        $c3 = "URLOpenStream"
        $c4 = "URLOpenPullStream"
    condition:
        $f1 and 1 of ($c*)
}

rule network_ftp : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over FTP"
	version = "0.1"
    strings:
	   $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory"
        $c2 = "FtpGetFile"
        $c3 = "FtpPutFile"
        $c4 = "FtpSetCurrentDirectory"
        $c5 = "FtpOpenFile"
        $c6 = "FtpGetFileSize"
        $c7 = "FtpDeleteFile"
        $c8 = "FtpCreateDirectory"
        $c9 = "FtpRemoveDirectory"
        $c10 = "FtpRenameFile"
        $c11 = "FtpDownload"
        $c12 = "FtpUpload"
        $c13 = "FtpGetDirectory"
    condition:
        $f1 and (4 of ($c*))
}

rule network_tcp_socket : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over RAW socket"
	version = "0.1"
    strings:
	$f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $c1 = "WSASocket"
        $c2 = "socket"
        $c3 = "send"
        $c4 = "WSASend"
        $c5 = "WSAConnect"
        $c6 = "connect"
        $c7 = "WSAStartup"
        $c8 = "closesocket"
        $c9 = "WSACleanup"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dns : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications use DNS"
	version = "0.1"
    strings:
        $f1 = "System.Net"
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase
        $c2 = "GetHostEntry"
	    $c3 = "getaddrinfo"
	    $c4 = "gethostbyname"
	    $c5 = "WSAAsyncGetHostByName"
	    $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*)
}

rule network_ssl : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule network_dga : NetworkCommunication {
    meta:
        author = "x0r"
        description = "Communication using dga"
	version = "0.1"
    strings:
        $dll1 = "Advapi32.dll" nocase
        $dll2 = "wininet.dll" nocase
	    $dll3 = "Crypt32.dll" nocase
        $time1 = "SystemTimeToFileTime"
        $time2 = "GetSystemTime"
        $time3 = "GetSystemTimeAsFileTime"
        $hash1 = "CryptCreateHash"
        $hash2 = "CryptAcquireContext"
        $hash3 = "CryptHashData"
        $net1 = "InternetOpen"
        $net2 = "InternetOpenUrl"
        $net3 = "gethostbyname"
        $net4 = "getaddrinfo"
    condition:
        all of ($dll*) and 1 of ($time*) and 1 of ($hash*) and 1 of ($net*)
}


rule bitcoin : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Perform crypto currency mining"
	version = "0.1"
    strings:
        $f1 = "OpenCL.dll" nocase
        $f2 = "nvcuda.dll" nocase
        $f3 = "opengl32.dll" nocase
        $s1 = "cpuminer 2.2.2X-Mining-Extensions"
        $s2 = "cpuminer 2.2.3X-Mining-Extensions"
	    $s3 = "Ufasoft bitcoin-miner/0.20"
	    $s4 = "bitcoin" nocase
	    $s5 = "stratum" nocase
    condition:
        1 of ($f*) and 1 of ($s*)
}

rule certificate : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Inject certificate in store"
	version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore"
    condition:
	all of them
}

rule escalate_priv : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Escalade priviledges"
	version = "0.1"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege"
        $c2 = "AdjustTokenPrivileges"
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule screenshot : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "May Take screenshot"
	version = "0.1"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt"
        $c2 = "GetDC"
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule lookupip : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Lookup external IP"
	version = "0.1"
    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule dyndns : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Dynamic DNS"
	version = "0.1"
    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Lookup Geolocation"
	version = "0.1"
    strings:
        $n1 = "j.maxmind.com" nocase
    condition:
        any of them
}

rule keylogger : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Run a keylogger"
	version = "0.1"
    strings:
	    $f1 = "User32.dll" nocase
        $c1 = "GetAsyncKeyState"
        $c2 = "GetKeyState"
        $c3 = "MapVirtualKey"
        $c4 = "GetKeyboardType"
    condition:
        $f1 and 1 of ($c*)
}

rule cred_local : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Steal credential"
	version = "0.1"
    strings:
        $c1 = "LsaEnumerateLogonSessions"
        $c2 = "SamIConnect"
        $c3 = "SamIGetPrivateData"
        $c4 = "SamQueryInformationUse"
        $c5 = "CredEnumerateA"
        $c6 = "CredEnumerateW"
        $r1 = "software\\microsoft\\internet account manager" nocase
        $r2 = "software\\microsoft\\identitycrl\\creds" nocase
        $r3 = "Security\\Policy\\Secrets"
    condition:
        any of them
}


rule sniff_audio : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Record Audio"
        version = "0.1"
    strings:
        $f1 = "winmm.dll" nocase
        $c1 = "waveInStart"
        $c2 = "waveInReset"
        $c3 = "waveInAddBuffer"
        $c4 = "waveInOpen"
        $c5 = "waveInClose"
    condition:
        $f1 and 2 of ($c*)
}

rule cred_ff : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Steal Firefox credential"
	version = "0.1"
    strings:
        $f1 = "signons.sqlite"
        $f2 = "signons3.txt"
        $f3 = "secmod.db"
        $f4 = "cert8.db"
        $f5 = "key3.db"
    condition:
        any of them
}

rule cred_vnc : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Steal VNC credential"
	version = "0.1"
    strings:
        $s1 = "VNCPassView"
    condition:
        all of them
}

rule cred_ie7 : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Steal IE 7 credential"
	version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $c1 = "CryptUnprotectData"
        $s1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" nocase
    condition:
        all of them
}

rule sniff_lan : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Sniff Lan network traffic"
	version = "0.1"
    strings:
        $f1 = "packet.dll" nocase
        $f2 = "npf.sys" nocase
        $f3 = "wpcap.dll" nocase
        $f4 = "winpcap.dll" nocase
    condition:
        any of them
}

rule migrate_apc : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "APC queue tasks migration"
	version = "0.1"
    strings:
        $c1 = "OpenThread"
        $c2 = "QueueUserAPC"
    condition:
        all of them
}

rule spreading_file : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Malware can spread east-west file"
	version = "0.1"
    strings:
        $f1 = "autorun.inf" nocase
        $f2 = "desktop.ini" nocase
        $f3 = "desktop.lnk" nocase
    condition:
        any of them
}

rule spreading_share : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Malware can spread east-west using share drive"
        version = "0.1"
    strings:
        $f1 = "netapi32.dll" nocase
        $c1 = "NetShareGetInfo"
        $c2 = "NetShareEnum"
    condition:
        $f1 and 1 of ($c*)
}

rule rat_vnc : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit VNC"
	version = "0.1"
    strings:
        $f1 = "ultravnc.ini" nocase
        $c2 = "StartVNC"
        $c3 = "StopVNC"
    condition:
        any of them
}

rule rat_rdp : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable RDP"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $c1 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}

rule rat_telnet : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable Telnet"
        version = "0.1"
    strings:
        $r1 = "software\\microsoft\\telnetserver" nocase
    condition:
        any of them
}


rule rat_webcam : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit using webcam"
        version = "0.1"
    strings:
        $f1 = "avicap32.dll" nocase
        $c1 = "capCreateCaptureWindow" nocase
    condition:
        all of them
}

rule check_patchlevel : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "Checks if hotfix are applied"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}

rule win_mutex : GenericActivity {
    meta:
        author = "x0r"
        description = "Create or check mutex"
    version = "0.1"
    strings:
        $c1 = "CreateMutex"
    condition:
        1 of ($c*)
}

rule win_registry : GenericActivity {
    meta:
        author = "x0r"
        description = "Affect system registries"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "RegQueryValueExA"
        $c2 = "RegOpenKeyExA"
        $c3 = "RegCloseKey"
        $c4 = "RegSetValueExA"
        $c5 = "RegCreateKeyA"
        $c6 = "RegCloseKey"
    condition:
        $f1 and 1 of ($c*)
}

rule win_token : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "May affect system token"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "DuplicateTokenEx"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "OpenProcessToken"
        $c4 = "LookupPrivilegeValueA"
    condition:
        $f1 and 1 of ($c*)
}

rule win_private_profile : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "May affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "GetPrivateProfileIntA"
        $c2 = "GetPrivateProfileStringA"
        $c3 = "WritePrivateProfileStringA"
    condition:
        $f1 and 1 of ($c*)
}

rule win_files_operation : GenericActivity {
    meta:
        author = "x0r"
        description = "May affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "WriteFile"
        $c2 = "SetFilePointer"
        $c3 = "WriteFile"
        $c4 = "ReadFile"
        $c5 = "DeleteFileA"
        $c6 = "CreateFileA"
        $c7 = "FindFirstFileA"
        $c8 = "MoveFileExA"
        $c9 = "FindClose"
        $c10 = "SetFileAttributesA"
        $c11 = "CopyFile"

    condition:
        $f1 and 3 of ($c*)
}


rule win_hook : SuspiciousActivity {
    meta:
        author = "x0r"
        description = "May affect hook table"
    version = "0.1"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"
    condition:
        $f1 and 1 of ($c*)
}

rule vmdetect_misc : AntiVM
{
	meta:
    		author = "@abhinavbom"
		maltype = "NA"
		version = "0.1"
		date = "31/10/2015"
		description = "Contains Anti-VM additional processes and driver names."
	strings:
		$vbox1 = "VBoxService" nocase ascii wide
		$vbox2 = "VBoxTray" nocase ascii wide
		$vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
		$vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

		$wine1 = "wine_get_unix_file_name" ascii wide

		$vmware1 = "vmmouse.sys" ascii wide
		$vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

		$miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
		$miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

		// Drivers
		$vmdrv1 = "hgfs.sys" ascii wide
		$vmdrv2 = "vmhgfs.sys" ascii wide
		$vmdrv3 = "prleth.sys" ascii wide
		$vmdrv4 = "prlfs.sys" ascii wide
		$vmdrv5 = "prlmouse.sys" ascii wide
		$vmdrv6 = "prlvideo.sys" ascii wide
		$vmdrv7 = "prl_pv32.sys" ascii wide
		$vmdrv8 = "vpc-s3.sys" ascii wide
		$vmdrv9 = "vmsrvc.sys" ascii wide
		$vmdrv10 = "vmx86.sys" ascii wide
		$vmdrv11 = "vmnet.sys" ascii wide

		// SYSTEM\ControlSet001\Services
		$vmsrvc1 = "vmicheartbeat" ascii wide
		$vmsrvc2 = "vmicvss" ascii wide
		$vmsrvc3 = "vmicshutdown" ascii wide
		$vmsrvc4 = "vmicexchange" ascii wide
		$vmsrvc5 = "vmci" ascii wide
		$vmsrvc6 = "vmdebug" ascii wide
		$vmsrvc7 = "vmmouse" ascii wide
		$vmsrvc8 = "VMTools" ascii wide
		$vmsrvc9 = "VMMEMCTL" ascii wide
		$vmsrvc10 = "vmware" ascii wide
		$vmsrvc11 = "vmx86" ascii wide
		$vmsrvc12 = "vpcbus" ascii wide
		$vmsrvc13 = "vpc-s3" ascii wide
		$vmsrvc14 = "vpcuhub" ascii wide
		$vmsrvc15 = "msvmmouf" ascii wide
		$vmsrvc16 = "VBoxMouse" ascii wide
		$vmsrvc17 = "VBoxGuest" ascii wide
		$vmsrvc18 = "VBoxSF" ascii wide
		$vmsrvc19 = "xenevtchn" ascii wide
		$vmsrvc20 = "xennet" ascii wide
		$vmsrvc21 = "xennet6" ascii wide
		$vmsrvc22 = "xensvc" ascii wide
		$vmsrvc23 = "xenvdb" ascii wide

		// Processes
		$miscproc1 = "vmware2" ascii wide
		$miscproc2 = "vmount2" ascii wide
		$miscproc3 = "vmusrvc" ascii wide
		$miscproc4 = "vmsrvc" ascii wide
		$miscproc5 = "vboxservice" ascii wide
		$miscproc6 = "vboxtray" ascii wide
		$miscproc7 = "xenservice" ascii wide

		$vmware_mac_1a = "00-05-69"
		$vmware_mac_1b = "00:05:69"
		$vmware_mac_2a = "00-50-56"
		$vmware_mac_2b = "00:50:56"
		$vmware_mac_3a = "00-0C-29"
		$vmware_mac_3b = "00:0C:29"
		$vmware_mac_4a = "00-1C-14"
		$vmware_mac_4b = "00:1C:14"
		$virtualbox_mac_1a = "08-00-27"
		$virtualbox_mac_1b = "08:00:27"

	condition:
		2 of them
}
