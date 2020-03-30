rule screenshot_MITRE___T1113 {
    meta:
        author = "x0r"
        description = "Takes screenshot"
	version = "0.1"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt"
        $c2 = "GetDC"
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule Run_Entry_MITRE___T1060 {
	    meta:
        description = "Registry Run Keys / Startup Folder"
    strings:
        $a0 = "(HKEY_CURRENT_USER|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $a1 = "(HKEY_CURRENT_USER|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
        $a2 = "(HKEY_LOCAL_MACHINE|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $a3 = "(HKEY_LOCAL_MACHINE|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
        $a4 = "(HKEY_LOCAL_MACHINE|HKLM)\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" nocase wide ascii
        $a5 = "RegSetValueExA" nocase wide ascii

    condition:
        ($a0 or $a1 or $a2 or $a3 or $a4) and $a5
}


rule cmd_MITRE___T1059 {
	    meta:
        description = "Command-Line Interface"
    strings:
        $a0 = "cmd.exe" nocase wide ascii

    condition:
        any of them
}


rule Startup_MITRE___T1060 {
	    meta:
        description = "May have dropper capabilities"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $a2 = "Programs\\Startup" nocase wide ascii
        $a4 = "%allusersprofile%" nocase wide ascii
    condition:
        all of them
}


rule AutoIT_MITRE___T1064 {
	    meta:
        description = "Scripting"
    strings:
        $a0 = "AutoIt Error" ascii wide
        $a1 = "reserved for AutoIt internal use" ascii wide
    condition:
        any of them
}


rule WMI_strings_MITRE___T1064 {
	    meta:
        description = "Scripting"
    strings:
        // WMI namespaces which may be referenced in the ConnectServer call. All in the form of "ROOT\something"
        $a0 = /ROOT\\(CIMV2|AccessLogging|ADFS|aspnet|Cli|Hardware|interop|InventoryLogging|Microsoft.{10}|Policy|RSOP|SECURITY|ServiceModel|snmpStandardCimv2|subscription|virtualization|WebAdministration|WMI)/ nocase ascii wide
    condition:
        any of them
}


rule Base64d_PE_MITRE___T1027 {
		meta:
		description = "Contains a base64-encoded executable"
		author = "Florian Roth"
		date = "2017-04-21"

	strings:
		$s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii

	condition:
		any of them
}

rule Token_Impersonation_MITRE___T1134 {
		meta:
		description = "Access Token Manipulation"

	strings:
		$s0 = "ImpersonateLoggedOnUser" wide ascii
		$s1 = "SetThreadToken" wide ascii

	condition:
		all of them
}


rule Create_Process_with_a_Token_MITRE___T1134 {
		meta:
		description = "Access Token Manipulation"

	strings:
		$s0 = "DuplicateToken" wide ascii
		$s1 = "CreateProcessWithTokenW" wide ascii

	condition:
		all of them
}


rule Make_and_Impersonate_Token_MITRE___T1135 {
		meta:
		description = "Access Token Manipulation"

	strings:
		$s0 = "LogonUser" wide ascii
		$s1 = "SetThreadToken" wide ascii

	condition:
		all of them
}


rule Disable_AV_MITRE___T1089 {
	    meta:
        description = "Disabling Security Tools"
        author = "Jerome Athias"
        source = "Metasploit's killav.rb script"

    strings:
        $a0 = "AAWTray.exe" nocase wide ascii
        $a1 = "Ad-Aware.exe" nocase wide ascii
        $a2 = "MSASCui.exe" nocase wide ascii
        $a3 = "_avp32.exe" nocase wide ascii
        $a4 = "_avpcc.exe" nocase wide ascii
        $a5 = "_avpm.exe" nocase wide ascii
        $a6 = "aAvgApi.exe" nocase wide ascii
        $a7 = "ackwin32.exe" nocase wide ascii
        $a8 = "adaware.exe" nocase wide ascii
        $a9 = "advxdwin.exe" nocase wide ascii
        $a10 = "agentsvr.exe" nocase wide ascii
        $a11 = "agentw.exe" nocase wide ascii
        $a12 = "alertsvc.exe" nocase wide ascii
        $a13 = "alevir.exe" nocase wide ascii
        $a14 = "alogserv.exe" nocase wide ascii
        $a15 = "amon9x.exe" nocase wide ascii
        $a16 = "anti-trojan.exe" nocase wide ascii
        $a17 = "antivirus.exe" nocase wide ascii
        $a18 = "ants.exe" nocase wide ascii
        $a19 = "apimonitor.exe" nocase wide ascii
        $a20 = "aplica32.exe" nocase wide ascii
        $a21 = "apvxdwin.exe" nocase wide ascii
        $a22 = "arr.exe" nocase wide ascii
        $a23 = "atcon.exe" nocase wide ascii
        $a24 = "atguard.exe" nocase wide ascii
        $a25 = "atro55en.exe" nocase wide ascii
        $a26 = "atupdater.exe" nocase wide ascii
        $a27 = "atwatch.exe" nocase wide ascii
        $a28 = "au.exe" nocase wide ascii
        $a29 = "aupdate.exe" nocase wide ascii
        $a31 = "autodown.exe" nocase wide ascii
        $a32 = "autotrace.exe" nocase wide ascii
        $a33 = "autoupdate.exe" nocase wide ascii
        $a34 = "avconsol.exe" nocase wide ascii
        $a35 = "ave32.exe" nocase wide ascii
        $a36 = "avgcc32.exe" nocase wide ascii
        $a37 = "avgctrl.exe" nocase wide ascii
        $a38 = "avgemc.exe" nocase wide ascii
        $a39 = "avgnt.exe" nocase wide ascii
        $a40 = "avgrsx.exe" nocase wide ascii
        $a41 = "avgserv.exe" nocase wide ascii
        $a42 = "avgserv9.exe" nocase wide ascii
        $a43 = /av(gui|guard|center|gtray|gidsagent|gwdsvc|grsa|gcsrva|gcsrvx).exe/ nocase wide ascii
        $a44 = "avgw.exe" nocase wide ascii
        $a45 = "avkpop.exe" nocase wide ascii
        $a46 = "avkserv.exe" nocase wide ascii
        $a47 = "avkservice.exe" nocase wide ascii
        $a48 = "avkwctl9.exe" nocase wide ascii
        $a49 = "avltmain.exe" nocase wide ascii
        $a50 = "avnt.exe" nocase wide ascii
        $a51 = "avp.exe" nocase wide ascii
        $a52 = "avp.exe" nocase wide ascii
        $a53 = "avp32.exe" nocase wide ascii
        $a54 = "avpcc.exe" nocase wide ascii
        $a55 = "avpdos32.exe" nocase wide ascii
        $a56 = "avpm.exe" nocase wide ascii
        $a57 = "avptc32.exe" nocase wide ascii
        $a58 = "avpupd.exe" nocase wide ascii
        $a59 = "avsched32.exe" nocase wide ascii
        $a60 = "avsynmgr.exe" nocase wide ascii
        $a61 = "avwin.exe" nocase wide ascii
        $a62 = "avwin95.exe" nocase wide ascii
        $a63 = "avwinnt.exe" nocase wide ascii
        $a64 = "avwupd.exe" nocase wide ascii
        $a65 = "avwupd32.exe" nocase wide ascii
        $a66 = "avwupsrv.exe" nocase wide ascii
        $a67 = "avxmonitor9x.exe" nocase wide ascii
        $a68 = "avxmonitornt.exe" nocase wide ascii
        $a69 = "avxquar.exe" nocase wide ascii
        $a73 = "beagle.exe" nocase wide ascii
        $a74 = "belt.exe" nocase wide ascii
        $a75 = "bidef.exe" nocase wide ascii
        $a76 = "bidserver.exe" nocase wide ascii
        $a77 = "bipcp.exe" nocase wide ascii
        $a79 = "bisp.exe" nocase wide ascii
        $a80 = "blackd.exe" nocase wide ascii
        $a81 = "blackice.exe" nocase wide ascii
        $a82 = "blink.exe" nocase wide ascii
        $a83 = "blss.exe" nocase wide ascii
        $a84 = "bootconf.exe" nocase wide ascii
        $a85 = "bootwarn.exe" nocase wide ascii
        $a86 = "borg2.exe" nocase wide ascii
        $a87 = "bpc.exe" nocase wide ascii
        $a89 = "bs120.exe" nocase wide ascii
        $a90 = "bundle.exe" nocase wide ascii
        $a91 = "bvt.exe" nocase wide ascii
        $a92 = "ccapp.exe" nocase wide ascii
        $a93 = "ccevtmgr.exe" nocase wide ascii
        $a94 = "ccpxysvc.exe" nocase wide ascii
        $a95 = "cdp.exe" nocase wide ascii
        $a96 = "cfd.exe" nocase wide ascii
        $a97 = "cfgwiz.exe" nocase wide ascii
        $a98 = "cfiadmin.exe" nocase wide ascii
        $a99 = "cfiaudit.exe" nocase wide ascii
        $a100 = "cfinet.exe" nocase wide ascii
        $a101 = "cfinet32.exe" nocase wide ascii
        $a102 = "claw95.exe" nocase wide ascii
        $a103 = "claw95cf.exe" nocase wide ascii
        $a104 = "clean.exe" nocase wide ascii
        $a105 = "cleaner.exe" nocase wide ascii
        $a106 = "cleaner3.exe" nocase wide ascii
        $a107 = "cleanpc.exe" nocase wide ascii
        $a108 = "click.exe" nocase wide ascii
        $a111 = "cmesys.exe" nocase wide ascii
        $a112 = "cmgrdian.exe" nocase wide ascii
        $a113 = "cmon016.exe" nocase wide ascii
        $a114 = "connectionmonitor.exe" nocase wide ascii
        $a115 = "cpd.exe" nocase wide ascii
        $a116 = "cpf9x206.exe" nocase wide ascii
        $a117 = "cpfnt206.exe" nocase wide ascii
        $a118 = "ctrl.exe" nocase wide ascii fullword
        $a119 = "cv.exe" nocase wide ascii
        $a120 = "cwnb181.exe" nocase wide ascii
        $a121 = "cwntdwmo.exe" nocase wide ascii
        $a123 = "dcomx.exe" nocase wide ascii
        $a124 = "defalert.exe" nocase wide ascii
        $a125 = "defscangui.exe" nocase wide ascii
        $a126 = "defwatch.exe" nocase wide ascii
        $a127 = "deputy.exe" nocase wide ascii
        $a129 = "dllcache.exe" nocase wide ascii
        $a130 = "dllreg.exe" nocase wide ascii
        $a132 = "dpf.exe" nocase wide ascii
        $a134 = "dpps2.exe" nocase wide ascii
        $a135 = "drwatson.exe" nocase wide ascii
        $a136 = "drweb32.exe" nocase wide ascii
        $a137 = "drwebupw.exe" nocase wide ascii
        $a138 = "dssagent.exe" nocase wide ascii
        $a139 = "dvp95.exe" nocase wide ascii
        $a140 = "dvp95_0.exe" nocase wide ascii
        $a141 = "ecengine.exe" nocase wide ascii
        $a142 = "efpeadm.exe" nocase wide ascii
        $a143 = "emsw.exe" nocase wide ascii
        $a145 = "esafe.exe" nocase wide ascii
        $a146 = "escanhnt.exe" nocase wide ascii
        $a147 = "escanv95.exe" nocase wide ascii
        $a148 = "espwatch.exe" nocase wide ascii
        $a150 = "etrustcipe.exe" nocase wide ascii
        $a151 = "evpn.exe" nocase wide ascii
        $a152 = "exantivirus-cnet.exe" nocase wide ascii
        $a153 = "exe.avxw.exe" nocase wide ascii
        $a154 = "expert.exe" nocase wide ascii
        $a156 = "f-agnt95.exe" nocase wide ascii
        $a157 = "f-prot.exe" nocase wide ascii
        $a158 = "f-prot95.exe" nocase wide ascii
        $a159 = "f-stopw.exe" nocase wide ascii
        $a160 = "fameh32.exe" nocase wide ascii
        $a161 = "fast.exe" nocase wide ascii
        $a162 = "fch32.exe" nocase wide ascii
        $a163 = "fih32.exe" nocase wide ascii
        $a164 = "findviru.exe" nocase wide ascii
        $a165 = "firewall.exe" nocase wide ascii
        $a166 = "fnrb32.exe" nocase wide ascii
        $a167 = "fp-win.exe" nocase wide ascii
        $a169 = "fprot.exe" nocase wide ascii
        $a170 = "frw.exe" nocase wide ascii
        $a171 = "fsaa.exe" nocase wide ascii
        $a172 = "fsav.exe" nocase wide ascii
        $a173 = "fsav32.exe" nocase wide ascii
        $a176 = "fsav95.exe" nocase wide ascii
        $a177 = "fsgk32.exe" nocase wide ascii
        $a178 = "fsm32.exe" nocase wide ascii
        $a179 = "fsma32.exe" nocase wide ascii
        $a180 = "fsmb32.exe" nocase wide ascii
        $a181 = "gator.exe" nocase wide ascii
        $a182 = "gbmenu.exe" nocase wide ascii
        $a183 = "gbpoll.exe" nocase wide ascii
        $a184 = "generics.exe" nocase wide ascii
        $a185 = "gmt.exe" nocase wide ascii
        $a186 = "guard.exe" nocase wide ascii
        $a187 = "guarddog.exe" nocase wide ascii
        $a189 = "hbinst.exe" nocase wide ascii
        $a190 = "hbsrv.exe" nocase wide ascii
        $a191 = "hotactio.exe" nocase wide ascii
        $a192 = "hotpatch.exe" nocase wide ascii
        $a193 = "htlog.exe" nocase wide ascii
        $a194 = "htpatch.exe" nocase wide ascii
        $a195 = "hwpe.exe" nocase wide ascii
        $a196 = "hxdl.exe" nocase wide ascii
        $a197 = "hxiul.exe" nocase wide ascii
        $a198 = "iamapp.exe" nocase wide ascii
        $a199 = "iamserv.exe" nocase wide ascii
        $a200 = "iamstats.exe" nocase wide ascii
        $a201 = "ibmasn.exe" nocase wide ascii
        $a202 = "ibmavsp.exe" nocase wide ascii
        $a203 = "icload95.exe" nocase wide ascii
        $a204 = "icloadnt.exe" nocase wide ascii
        $a205 = "icmon.exe" nocase wide ascii
        $a206 = "icsupp95.exe" nocase wide ascii
        $a207 = "icsuppnt.exe" nocase wide ascii
        $a209 = "iedll.exe" nocase wide ascii
        $a210 = "iedriver.exe" nocase wide ascii
        $a212 = "iface.exe" nocase wide ascii
        $a213 = "ifw2000.exe" nocase wide ascii
        $a214 = "inetlnfo.exe" nocase wide ascii
        $a215 = "infus.exe" nocase wide ascii
        $a216 = "infwin.exe" nocase wide ascii
        $a218 = "intdel.exe" nocase wide ascii
        $a219 = "intren.exe" nocase wide ascii
        $a220 = "iomon98.exe" nocase wide ascii
        $a221 = "istsvc.exe" nocase wide ascii
        $a222 = "jammer.exe" nocase wide ascii
        $a224 = "jedi.exe" nocase wide ascii
        $a227 = "kavpf.exe" nocase wide ascii
        $a228 = "kazza.exe" nocase wide ascii
        $a229 = "keenvalue.exe" nocase wide ascii
        $a236 = "ldnetmon.exe" nocase wide ascii
        $a237 = "ldpro.exe" nocase wide ascii
        $a238 = "ldpromenu.exe" nocase wide ascii
        $a239 = "ldscan.exe" nocase wide ascii
        $a240 = "lnetinfo.exe" nocase wide ascii
        $a242 = "localnet.exe" nocase wide ascii
        $a243 = "lockdown.exe" nocase wide ascii
        $a244 = "lockdown2000.exe" nocase wide ascii
        $a245 = "lookout.exe" nocase wide ascii
        $a248 = "luall.exe" nocase wide ascii
        $a249 = "luau.exe" nocase wide ascii
        $a250 = "lucomserver.exe" nocase wide ascii
        $a251 = "luinit.exe" nocase wide ascii
        $a252 = "luspt.exe" nocase wide ascii
        $a253 = "mapisvc32.exe" nocase wide ascii
        $a254 = "mcagent.exe" nocase wide ascii
        $a255 = "mcmnhdlr.exe" nocase wide ascii
        $a256 = "mcshield.exe" nocase wide ascii
        $a257 = "mctool.exe" nocase wide ascii
        $a258 = "mcupdate.exe" nocase wide ascii
        $a259 = "mcvsrte.exe" nocase wide ascii
        $a260 = "mcvsshld.exe" nocase wide ascii
        $a262 = "mfin32.exe" nocase wide ascii
        $a263 = "mfw2en.exe" nocase wide ascii
        $a265 = "mgavrtcl.exe" nocase wide ascii
        $a266 = "mgavrte.exe" nocase wide ascii
        $a267 = "mghtml.exe" nocase wide ascii
        $a268 = "mgui.exe" nocase wide ascii
        $a269 = "minilog.exe" nocase wide ascii
        $a270 = "mmod.exe" nocase wide ascii
        $a271 = "monitor.exe" nocase wide ascii
        $a272 = "moolive.exe" nocase wide ascii
        $a273 = "mostat.exe" nocase wide ascii
        $a274 = "mpfagent.exe" nocase wide ascii
        $a275 = "mpfservice.exe" nocase wide ascii
        $a276 = "mpftray.exe" nocase wide ascii
        $a277 = "mrflux.exe" nocase wide ascii
        $a278 = "msapp.exe" nocase wide ascii
        $a279 = "msbb.exe" nocase wide ascii
        $a280 = "msblast.exe" nocase wide ascii
        $a281 = "mscache.exe" nocase wide ascii
        $a282 = "msccn32.exe" nocase wide ascii
        $a283 = "mscman.exe" nocase wide ascii
        $a285 = "msdm.exe" nocase wide ascii
        $a286 = "msdos.exe" nocase wide ascii
        $a287 = "msiexec16.exe" nocase wide ascii
        $a288 = "msinfo32.exe" nocase wide ascii
        $a289 = "mslaugh.exe" nocase wide ascii
        $a290 = "msmgt.exe" nocase wide ascii
        $a291 = "msmsgri32.exe" nocase wide ascii
        $a292 = "mssmmc32.exe" nocase wide ascii
        $a293 = "mssys.exe" nocase wide ascii
        $a294 = "msvxd.exe" nocase wide ascii
        $a295 = "mu0311ad.exe" nocase wide ascii
        $a296 = "mwatch.exe" nocase wide ascii
        $a297 = "n32scanw.exe" nocase wide ascii
        $a298 = "nav.exe" nocase wide ascii
        $a300 = "navapsvc.exe" nocase wide ascii
        $a301 = "navapw32.exe" nocase wide ascii
        $a302 = "navdx.exe" nocase wide ascii
        $a303 = "navlu32.exe" nocase wide ascii
        $a304 = "navnt.exe" nocase wide ascii
        $a305 = "navstub.exe" nocase wide ascii
        $a306 = "navw32.exe" nocase wide ascii
        $a307 = "navwnt.exe" nocase wide ascii
        $a308 = "nc2000.exe" nocase wide ascii
        $a309 = "ncinst4.exe" nocase wide ascii
        $a310 = "ndd32.exe" nocase wide ascii
        $a311 = "neomonitor.exe" nocase wide ascii
        $a312 = "neowatchlog.exe" nocase wide ascii
        $a313 = "netarmor.exe" nocase wide ascii
        $a314 = "netd32.exe" nocase wide ascii
        $a315 = "netinfo.exe" nocase wide ascii
        $a317 = "netscanpro.exe" nocase wide ascii
        $a320 = "netutils.exe" nocase wide ascii
        $a321 = "nisserv.exe" nocase wide ascii
        $a322 = "nisum.exe" nocase wide ascii
        $a323 = "nmain.exe" nocase wide ascii
        $a324 = "nod32.exe" nocase wide ascii
        $a325 = "normist.exe" nocase wide ascii
        $a327 = "notstart.exe" nocase wide ascii
        $a329 = "npfmessenger.exe" nocase wide ascii
        $a330 = "nprotect.exe" nocase wide ascii
        $a331 = "npscheck.exe" nocase wide ascii
        $a332 = "npssvc.exe" nocase wide ascii
        $a333 = "nsched32.exe" nocase wide ascii
        $a334 = "nssys32.exe" nocase wide ascii
        $a335 = "nstask32.exe" nocase wide ascii
        $a336 = "nsupdate.exe" nocase wide ascii
        $a338 = "ntrtscan.exe" nocase wide ascii
        $a340 = "ntxconfig.exe" nocase wide ascii
        $a341 = "nui.exe" nocase wide ascii
        $a342 = "nupgrade.exe" nocase wide ascii
        $a343 = "nvarch16.exe" nocase wide ascii
        $a344 = "nvc95.exe" nocase wide ascii
        $a345 = "nvsvc32.exe" nocase wide ascii
        $a346 = "nwinst4.exe" nocase wide ascii
        $a347 = "nwservice.exe" nocase wide ascii
        $a348 = "nwtool16.exe" nocase wide ascii
        $a350 = "onsrvr.exe" nocase wide ascii
        $a351 = "optimize.exe" nocase wide ascii
        $a352 = "ostronet.exe" nocase wide ascii
        $a353 = "otfix.exe" nocase wide ascii
        $a354 = "outpost.exe" nocase wide ascii
        $a360 = "pavcl.exe" nocase wide ascii
        $a361 = "pavproxy.exe" nocase wide ascii
        $a362 = "pavsched.exe" nocase wide ascii
        $a363 = "pavw.exe" nocase wide ascii
        $a364 = "pccwin98.exe" nocase wide ascii
        $a365 = "pcfwallicon.exe" nocase wide ascii
        $a367 = "pcscan.exe" nocase wide ascii
        $a369 = "periscope.exe" nocase wide ascii
        $a370 = "persfw.exe" nocase wide ascii
        $a371 = "perswf.exe" nocase wide ascii
        $a372 = "pf2.exe" nocase wide ascii
        $a373 = "pfwadmin.exe" nocase wide ascii
        $a374 = "pgmonitr.exe" nocase wide ascii
        $a375 = "pingscan.exe" nocase wide ascii
        $a376 = "platin.exe" nocase wide ascii
        $a377 = "pop3trap.exe" nocase wide ascii
        $a378 = "poproxy.exe" nocase wide ascii
        $a379 = "popscan.exe" nocase wide ascii
        $a380 = "portdetective.exe" nocase wide ascii
        $a381 = "portmonitor.exe" nocase wide ascii
        $a382 = "powerscan.exe" nocase wide ascii
        $a383 = "ppinupdt.exe" nocase wide ascii
        $a384 = "pptbc.exe" nocase wide ascii
        $a385 = "ppvstop.exe" nocase wide ascii
        $a387 = "prmt.exe" nocase wide ascii
        $a388 = "prmvr.exe" nocase wide ascii
        $a389 = "procdump.exe" nocase wide ascii
        $a390 = "processmonitor.exe" nocase wide ascii
        $a392 = "programauditor.exe" nocase wide ascii
        $a393 = "proport.exe" nocase wide ascii
        $a394 = "protectx.exe" nocase wide ascii
        $a395 = "pspf.exe" nocase wide ascii
        $a396 = "purge.exe" nocase wide ascii
        $a397 = "qconsole.exe" nocase wide ascii
        $a398 = "qserver.exe" nocase wide ascii
        $a399 = "rapapp.exe" nocase wide ascii
        $a400 = "rav7.exe" nocase wide ascii
        $a401 = "rav7win.exe" nocase wide ascii
        $a404 = "rb32.exe" nocase wide ascii
        $a405 = "rcsync.exe" nocase wide ascii
        $a406 = "realmon.exe" nocase wide ascii
        $a407 = "reged.exe" nocase wide ascii
        $a410 = "rescue.exe" nocase wide ascii
        $a412 = "rrguard.exe" nocase wide ascii
        $a413 = "rshell.exe" nocase wide ascii
        $a414 = "rtvscan.exe" nocase wide ascii
        $a415 = "rtvscn95.exe" nocase wide ascii
        $a416 = "rulaunch.exe" nocase wide ascii
        $a421 = "safeweb.exe" nocase wide ascii
        $a422 = "sahagent.exe" nocase wide ascii
        $a424 = "savenow.exe" nocase wide ascii
        $a425 = "sbserv.exe" nocase wide ascii
        $a428 = "scan32.exe" nocase wide ascii
        $a430 = "scanpm.exe" nocase wide ascii
        $a431 = "scrscan.exe" nocase wide ascii
        $a435 = "sfc.exe" nocase wide ascii
        $a436 = "sgssfw32.exe" nocase wide ascii
        $a439 = "shn.exe" nocase wide ascii
        $a440 = "showbehind.exe" nocase wide ascii
        $a441 = "smc.exe" nocase wide ascii
        $a442 = "sms.exe" nocase wide ascii
        $a443 = "smss32.exe" nocase wide ascii
        $a445 = "sofi.exe" nocase wide ascii
        $a447 = "spf.exe" nocase wide ascii
        $a449 = "spoler.exe" nocase wide ascii
        $a450 = "spoolcv.exe" nocase wide ascii
        $a451 = "spoolsv32.exe" nocase wide ascii
        $a452 = "spyxx.exe" nocase wide ascii
        $a453 = "srexe.exe" nocase wide ascii
        $a454 = "srng.exe" nocase wide ascii
        $a455 = "ss3edit.exe" nocase wide ascii
        $a457 = "ssgrate.exe" nocase wide ascii
        $a458 = "st2.exe" nocase wide ascii fullword
        $a461 = "supftrl.exe" nocase wide ascii
        $a470 = "symproxysvc.exe" nocase wide ascii
        $a471 = "symtray.exe" nocase wide ascii
        $a472 = "sysedit.exe" nocase wide ascii
        $a480 = "taumon.exe" nocase wide ascii
        $a481 = "tbscan.exe" nocase wide ascii
        $a483 = "tca.exe" nocase wide ascii
        $a484 = "tcm.exe" nocase wide ascii
        $a488 = "teekids.exe" nocase wide ascii
        $a489 = "tfak.exe" nocase wide ascii
        $a490 = "tfak5.exe" nocase wide ascii
        $a491 = "tgbob.exe" nocase wide ascii
        $a492 = "titanin.exe" nocase wide ascii
        $a493 = "titaninxp.exe" nocase wide ascii
        $a496 = "trjscan.exe" nocase wide ascii
        $a500 = "tvmd.exe" nocase wide ascii
        $a501 = "tvtmd.exe" nocase wide ascii
        $a513 = "vet32.exe" nocase wide ascii
        $a514 = "vet95.exe" nocase wide ascii
        $a515 = "vettray.exe" nocase wide ascii
        $a517 = "vir-help.exe" nocase wide ascii
        $a519 = "vnlan300.exe" nocase wide ascii
        $a520 = "vnpc3000.exe" nocase wide ascii
        $a521 = "vpc32.exe" nocase wide ascii
        $a522 = "vpc42.exe" nocase wide ascii
        $a523 = "vpfw30s.exe" nocase wide ascii
        $a524 = "vptray.exe" nocase wide ascii
        $a525 = "vscan40.exe" nocase wide ascii
        $a527 = "vsched.exe" nocase wide ascii
        $a528 = "vsecomr.exe" nocase wide ascii
        $a529 = "vshwin32.exe" nocase wide ascii
        $a531 = "vsmain.exe" nocase wide ascii
        $a532 = "vsmon.exe" nocase wide ascii
        $a533 = "vsstat.exe" nocase wide ascii
        $a534 = "vswin9xe.exe" nocase wide ascii
        $a535 = "vswinntse.exe" nocase wide ascii
        $a536 = "vswinperse.exe" nocase wide ascii
        $a537 = "w32dsm89.exe" nocase wide ascii
        $a538 = "w9x.exe" nocase wide ascii
        $a541 = "webscanx.exe" nocase wide ascii
        $a543 = "wfindv32.exe" nocase wide ascii
        $a545 = "wimmun32.exe" nocase wide ascii
        $a566 = "wnad.exe" nocase wide ascii
        $a567 = "wnt.exe" nocase wide ascii
        $a568 = "wradmin.exe" nocase wide ascii
        $a569 = "wrctrl.exe" nocase wide ascii
        $a570 = "wsbgate.exe" nocase wide ascii
        $a573 = "wyvernworksfirewall.exe" nocase wide ascii
        $a575 = "zapro.exe" nocase wide ascii
        $a577 = "zatutor.exe" nocase wide ascii
        $a579 = "zonealarm.exe" nocase wide ascii
		// Strings from Dubnium below
		$a580 = "QQPCRTP.exe" nocase wide ascii
		$a581 = "QQPCTray.exe" nocase wide ascii
		$a582 = "ZhuDongFangYu.exe" nocase wide ascii
		$a583 = /360(tray|sd|rp).exe/ nocase wide ascii
		$a584 = /qh(safetray|watchdog|activedefense).exe/ nocase wide ascii
		$a585 = "McNASvc.exe" nocase wide ascii
		$a586 = "MpfSrv.exe" nocase wide ascii
		$a587 = "McProxy.exe" nocase wide ascii
		$a588 = "mcmscsvc.exe" nocase wide ascii
		$a589 = "McUICnt.exe" nocase wide ascii
		$a590 = /ui(WatchDog|seagnt|winmgr).exe/ nocase wide ascii
		$a591 = "ufseagnt.exe" nocase wide ascii
		$a592 = /core(serviceshell|frameworkhost).exe/ nocase wide ascii
		$a593 = /ay(agent|rtsrv|updsrv).aye/ nocase wide ascii
		$a594 = /avast(ui|svc).exe/ nocase wide ascii
		$a595 = /ms(seces|mpeng).exe/ nocase wide ascii
		$a596 = "afwserv.exe" nocase wide ascii
		$a597 = "FiddlerUser"

    condition:
        any of them
}

rule antianalysis_detectfile_MITRE___T1063 {

    meta:
        name = "antianalysis_detectfile"

    strings:
        $a1 = "[A-Za-z]:\\\\analysis"
        $a2 = "[A-Za-z]:\\\\iDEFENSE"
        $a3 = "[A-Za-z]:\\\\stuff\\\\odbg110"
        $a4 = "[A-Za-z]:\\\\gnu\\\\bin"
        $a5 = "[A-Za-z]:\\\\Virus\\ Analysis"
        $a6 = "[A-Za-z]:\\\\popupkiller\\.exe"
        $a7 = "[A-Za-z]:\\\\tools\\\\execute\\.exe"
        $a8 = "[A-Za-z]:\\\\MDS\\\\WinDump\\.exe"
        $a9 = "[A-Za-z]:\\\\guest_tools\\\\start\\.bat"
        $a10 = "[A-Za-z]:\\\\tools\\\\aswsnx"
        $a11 = "[A-Za-z]:\\\\tools\\\\decodezeus"
        $a12 = "[A-Za-z]:\\\\tool\\\\malmon"
        $a13 = "[A-Za-z]:\\\\sandcastle\\\\tools"
        $a14 = "[A-Za-z]:\\\\tsl\\\\raptorclient\\.exe"
        $a15 = "[A-Za-z]:\\\\kit\\\\procexp\\.exe"
        $a16 = "[A-Za-z]:\\\\winap\\\\ckmon\\.pyw"
        $a17 = "[A-Za-z]:\\\\vmremote\\\\vmremoteguest\\.exe"
        $a18 = "[A-Za-z]:\\\\Program\\ Files(\\ \\(x86\\))?\\\\Fiddler"
        $a19 = "[A-Za-z]:\\\\ComboFix"

    condition:
        any of them

}

rule Big_Numbers0_MITRE___T1032_T1022 {
		meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}

rule Big_Numbers1_MITRE___T1032_T1022 {
		meta:
		author = "_pusher_"
		description = "Looks for big numbers 32:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers2_MITRE___T1032_T1022 {
		meta:
		author = "_pusher_"
		description = "Looks for big numbers 48:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{48}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers3_MITRE___T1032_T1022 {
		meta:
		author = "_pusher_"
		description = "Looks for big numbers 64:sized"
		date = "2016-07"
	strings:
        	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers4_MITRE___T1032_T1022 {
		meta:
		author = "_pusher_"
		description = "Looks for big numbers 128:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers5_MITRE___T1032_T1022 {
		meta:
		author = "_pusher_"
		description = "Looks for big numbers 256:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
	condition:
		$c0
}

rule Prime_Constants_char_MITRE___T1032_T1022_ {
	meta:
		author = "_pusher_"
		description = "List of primes [char]"
		date = "2016-07"
	strings:
		$c0 = { 03 05 07 0B 0D 11 13 17 1D 1F 25 29 2B 2F 35 3B 3D 43 47 49 4F 53 59 61 65 67 6B 6D 71 7F 83 89 8B 95 97 9D A3 A7 AD B3 B5 BF C1 C5 C7 D3 DF E3 E5 E9 EF F1 FB }
	condition:
		$c0
}

rule Prime_Constants_long_MITRE___T1032_T1022_ {
	meta:
		author = "_pusher_"
		description = "List of primes [long]"
		date = "2016-07"
	strings:
		$c0 = { 03 00 00 00 05 00 00 00 07 00 00 00 0B 00 00 00 0D 00 00 00 11 00 00 00 13 00 00 00 17 00 00 00 1D 00 00 00 1F 00 00 00 25 00 00 00 29 00 00 00 2B 00 00 00 2F 00 00 00 35 00 00 00 3B 00 00 00 3D 00 00 00 43 00 00 00 47 00 00 00 49 00 00 00 4F 00 00 00 53 00 00 00 59 00 00 00 61 00 00 00 65 00 00 00 67 00 00 00 6B 00 00 00 6D 00 00 00 71 00 00 00 7F 00 00 00 83 00 00 00 89 00 00 00 8B 00 00 00 95 00 00 00 97 00 00 00 9D 00 00 00 A3 00 00 00 A7 00 00 00 AD 00 00 00 B3 00 00 00 B5 00 00 00 BF 00 00 00 C1 00 00 00 C5 00 00 00 C7 00 00 00 D3 00 00 00 DF 00 00 00 E3 00 00 00 E5 00 00 00 E9 00 00 00 EF 00 00 00 F1 00 00 00 FB 00 00 00 }
	condition:
		$c0
}


rule Advapi_Hash_API_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Looks for advapi API functions"
		date = "2016-07"
	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$CryptCreateHash = "CryptCreateHash" wide ascii
		$CryptHashData = "CryptHashData" wide ascii
		$CryptAcquireContext = "CryptAcquireContext" wide ascii
	condition:
		$advapi32 and ($CryptCreateHash and $CryptHashData and $CryptAcquireContext)
}

rule Crypt32_CryptBinaryToString_API_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Looks for crypt32 CryptBinaryToStringA function"
		date = "2016-08"
	strings:
		$crypt32 = "crypt32.dll" wide ascii nocase
		$CryptBinaryToStringA = "CryptBinaryToStringA" wide ascii
	condition:
		$crypt32 and ($CryptBinaryToStringA)
}

rule CRC32c_poly_Constant_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for CRC32c (Castagnoli) [poly]"
		date = "2016-08"
	strings:
		$c0 = { 783BF682 }
	condition:
		$c0
}

rule CRC32_poly_Constant_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for CRC32 [poly]"
		date = "2015-05"
		version = "0.1"
	strings:
		$c0 = { 2083B8ED }
	condition:
		$c0
}

rule CRC32_table_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for CRC32 table"
		date = "2015-05"
		version = "0.1"
	strings:
		$c0 = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 }
	condition:
		$c0
}

rule CRC32_table_lookup_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "CRC32 table lookup"
		date = "2015-06"
		version = "0.1"
	strings:
		$c0 = { 8B 54 24 08 85 D2 7F 03 33 C0 C3 83 C8 FF 33 C9 85 D2 7E 29 56 8B 74 24 08 57 8D 9B 00 00 00 00 0F B6 3C 31 33 F8 81 E7 FF 00 00 00 C1 E8 08 33 04 BD ?? ?? ?? ?? 41 3B CA 7C E5 5F 5E F7 D0 C3 }
	condition:
		$c0
}

rule CRC32b_poly_Constant_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for CRC32b [poly]"
		date = "2016-04"
		version = "0.1"
	strings:
		$c0 = { B71DC104 }
	condition:
		$c0
}


rule CRC16_table_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for CRC16 table"
		date = "2016-04"
		version = "0.1"
	strings:
		$c0 = { 00 00 21 10 42 20 63 30 84 40 A5 50 C6 60 E7 70 08 81 29 91 4A A1 6B B1 8C C1 AD D1 CE E1 EF F1 31 12 10 02 73 32 52 22 B5 52 94 42 F7 72 D6 62 39 93 18 83 7B B3 5A A3 BD D3 9C C3 FF F3 DE E3 }
	condition:
		$c0
}


rule FlyUtilsCnDES_ECB_Encrypt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for FlyUtils.CnDES Encrypt ECB function"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D E8 89 5D EC 8B D9 89 55 F8 89 45 FC 8B 7D 08 8B 75 20 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 80 7D 18 00 74 1A 0F B6 55 18 8D 4D EC 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 EC 8D 45 F8 E8 ?? ?? ?? ?? 80 7D 1C 00 74 1A 0F B6 55 1C 8D 4D E8 8B 45 FC E8 ?? ?? ?? ?? 8B 55 E8 8D 45 FC E8 ?? ?? ?? ?? 85 DB 75 07 E8 ?? ?? ?? ?? 8B D8 85 F6 75 07 E8 ?? ?? ?? ?? 8B F0 53 6A 00 8B 4D FC B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 8B 45 F4 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 6A 00 33 C9 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F0 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 56 }
	condition:
		$c0
}

rule FlyUtilsCnDES_ECB_Decrypt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for FlyUtils.CnDES Decrypt ECB function"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D E8 89 5D EC 8B F9 89 55 F8 89 45 FC 8B 5D 18 8B 75 20 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 84 DB 74 18 8B D3 8D 4D EC 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 EC 8D 45 F8 E8 ?? ?? ?? ?? 85 FF 75 07 E8 ?? ?? ?? ?? 8B F8 85 F6 75 07 E8 ?? ?? ?? ?? 8B F0 8B 4D FC B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 57 6A 00 33 C9 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F0 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 FF 75 14 FF 75 10 8B 45 0C 50 8B 4D F8 8B 55 F0 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 6A 00 8B 45 F0 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 08 8B 45 F0 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB 12 E9 ?? ?? ?? ?? 8B 45 08 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F0 33 D2 89 55 F0 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule Elf_Hash_MITRE___T1032_T1022_ {
	meta:
		author = "_pusher_"
		description = "Look for ElfHash"
		date = "2015-06"
		version = "0.3"
	strings:
		$c0 = { 53 56 33 C9 8B DA 4B 85 DB 7C 25 43 C1 E1 04 33 D2 8A 10 03 CA 8B D1 81 E2 00 00 00 F0 85 D2 74 07 8B F2 C1 EE 18 33 CE F7 D2 23 CA 40 4B 75 DC 8B C1 5E 5B C3 }
		$c1 = { 53 33 D2 85 C0 74 2B EB 23 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 D7 8B C2 5B C3 }
		$c2 = { 53 56 33 C9 8B D8 85 D2 76 23 C1 E1 04 33 C0 8A 03 03 C8 8B C1 25 00 00 00 F0 85 C0 74 07 8B F0 C1 EE 18 33 CE F7 D0 23 C8 43 4A 75 DD 8B C1 5E 5B C3 }
		$c3 = { 53 56 57 8B F2 8B D8 8B FB 53 E8 ?? ?? ?? ?? 6B C0 02 71 05 E8 ?? ?? ?? ?? 8B D7 33 C9 8B D8 83 EB 01 71 05 E8 ?? ?? ?? ?? 85 DB 7C 2C 43 C1 E1 04 0F B6 02 03 C8 71 05 E8 ?? ?? ?? ?? 83 C2 01 B8 00 00 00 F0 23 C1 85 C0 74 07 8B F8 C1 EF 18 33 CF F7 D0 23 C8 4B 75 D5 8B C1 99 F7 FE 8B C2 85 C0 7D 09 03 C6 71 05 E8 ?? ?? ?? ?? 5F 5E 5B C3 }
		$c4 = { 53 33 D2 EB 2C 8B D9 80 C3 BF 80 EB 1A 73 03 80 C1 20 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 CE 8B C2 5B C3 }
		$c5 = { 89 C2 31 C0 85 D2 74 30 2B 42 FC 74 2B 89 C1 29 C2 31 C0 53 0F B6 1C 11 01 C3 8D 04 1B C1 EB 14 8D 04 C5 00 00 00 00 81 E3 00 0F 00 00 31 D8 83 C1 01 75 E0 C1 E8 04 5B C3 }
		$c6 = { 53 33 D2 85 C0 74 38 EB 30 8B D9 80 C3 BF 80 EB 1A 73 03 80 C1 20 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 CA 8B C2 5B C3 }
	condition:
		any of them
}

rule BLOWFISH_Constants_MITRE___T1032_T1022 {
	meta:
		author = "phoul (@phoul)"
		description = "Look for Blowfish constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
		6 of them
}

rule MD5_Constants_MITRE___T1032_T1022 {
	meta:
		author = "phoul (@phoul)"
		description = "Look for MD5 constants"
		date = "2014-01"
		version = "0.2"
	strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
		5 of them
}

rule MD5_API_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Looks for MD5 API"
		date = "2016-07"
	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$cryptdll = "cryptdll.dll" wide ascii nocase
		$MD5Init = "MD5Init" wide ascii
		$MD5Update = "MD5Update" wide ascii
		$MD5Final = "MD5Final" wide ascii
	condition:
		($advapi32 or $cryptdll) and ($MD5Init and $MD5Update and $MD5Final)
}

rule RC6_Constants_MITRE___T1032_T1022 {
	meta:
		author = "chort (@chort0)"
		description = "Look for RC6 magic constants in binary"
		reference = "https://twitter.com/mikko/status/417620511397400576"
		reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
		date = "2013-12"
		version = "0.2"
	strings:
		$c1 = { B7E15163 }
		$c2 = { 9E3779B9 }
		$c3 = { 6351E1B7 }
		$c4 = { B979379E }
	condition:
		2 of them
}

rule RIPEMD160_Constants_MITRE___T1032_T1022 {
	meta:
		author = "phoul (@phoul)"
		description = "Look for RIPEMD-160 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}

rule SHA1_Constants_MITRE___T1032_T1022 {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA1 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
		//added by _pusher_ 2016-07 - last round
		$c10 = { D6C162CA }
	condition:
		5 of them
}

rule SHA512_Constants_MITRE___T1032_T1022 {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA384/SHA512 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}

rule TEAN_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for TEA Encryption"
		date = "2016-08"
	strings:
		$c0 = { 2037EFC6 }
	condition:
		$c0
}

rule WHIRLPOOL_Constants_MITRE___T1032_T1022 {
	meta:
		author = "phoul (@phoul)"
		description = "Look for WhirlPool constants"
		date = "2014-02"
		version = "0.1"
	strings:
		$c0 = { 18186018c07830d8 }
		$c1 = { d83078c018601818 }
		$c2 = { 23238c2305af4626 }
		$c3 = { 2646af05238c2323 }
	condition:
		2 of them
}

rule DarkEYEv3_Cryptor_MITRE___T1032_T1022 {
	meta:
		description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
		author = "Florian Roth"
		reference = "http://darkeyev3.blogspot.fi/"
		date = "2015-05-24"
		hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
		hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
		hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
		hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
		hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
		hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
		hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
		hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
		hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"
		score = 55
	strings:
		$s0 = "\\DarkEYEV3-"
	condition:
		uint16(0) == 0x5a4d and $s0
}

rule Miracl_powmod_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "Miracl powmod"
	strings:
		$c0 = { 53 55 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 0F 85 EC 01 00 00 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 12 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 06 8B 4E 10 3B C1 74 2E 8B 7C 24 1C 57 E8 ?? ?? ?? ?? 83 C4 04 83 F8 02 7C 33 8B 57 04 8B 0E 51 8B 02 50 E8 ?? ?? ?? ?? 83 C4 08 83 F8 01 0F 84 58 01 00 00 EB 17 8B 7C 24 1C 6A 02 57 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 3F 01 00 00 8B 8E C4 01 00 00 8B 54 24 18 51 52 E8 ?? ?? ?? ?? 8B 86 CC }
	condition:
		$c0
}

rule Miracl_crt_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "Miracl crt"
	strings:
		$c0 = { 51 56 57 E8 ?? ?? ?? ?? 8B 74 24 10 8B F8 89 7C 24 08 83 7E 0C 02 0F 8C 99 01 00 00 8B 87 18 02 00 00 85 C0 0F 85 8B 01 00 00 8B 57 1C 42 8B C2 89 57 1C 83 F8 18 7D 17 C7 44 87 20 4A 00 00 00 8B 87 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 46 04 8B 54 24 14 53 55 8B 08 8B 02 51 50 E8 ?? ?? ?? ?? 8B 4E 0C B8 01 00 00 00 83 C4 08 33 ED 3B C8 89 44 24 18 0F 8E C5 00 00 00 BF 04 00 00 00 8B 46 04 8B 0C 07 8B 10 8B 44 24 1C 51 52 8B 0C 07 51 E8 ?? ?? ?? ?? 8B 56 04 8B 4E 08 8B 04 }
	condition:
		$c0
}

rule CryptoPP_a_exp_b_mod_c_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "CryptoPP a_exp_b_mod_c"
	strings:
		$c0 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC ?? 00 00 00 56 8B B4 24 B0 00 00 00 57 6A 00 8B CE C7 44 24 0C 00 00 00 00 E8 ?? ?? ?? ?? 84 C0 0F 85 16 01 00 00 8D 4C 24 24 E8 ?? ?? ?? ?? BF 01 00 00 00 56 8D 4C 24 34 89 BC 24 A4 00 00 00 E8 ?? ?? ?? ?? 8B 06 8D 4C 24 3C 50 6A 00 C6 84 24 A8 00 00 00 02 E8 ?? ?? ?? ?? 8D 4C 24 48 C6 84 24 A0 00 00 00 03 E8 ?? ?? ?? ?? C7 44 24 24 ?? ?? ?? ?? 8B 8C 24 AC 00 00 00 8D 54 24 0C 51 52 8D 4C 24 2C C7 84 24 A8 }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 4C 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 70 8D 4C 24 18 56 89 7C 24 60 E8 ?? ?? ?? ?? 8B 76 08 8D 4C 24 2C 56 57 C6 44 24 64 01 E8 ?? ?? ?? ?? 8D 4C 24 40 C6 44 24 5C 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 4C 24 6C 8B 54 24 68 8B 74 24 64 51 52 56 8D 4C 24 18 C7 44 24 68 03 00 00 00 E8 ?? ?? ?? ?? 8B 7C 24 4C 8B 4C 24 48 8B D7 33 C0 F3 }
		$c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 34 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 58 8D 4C 24 18 56 89 7C 24 48 E8 ?? ?? ?? ?? 8B 0E C6 44 24 44 01 51 57 8D 4C 24 2C E8 ?? ?? ?? ?? 8D 4C 24 30 C6 44 24 44 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 54 24 54 8B 44 24 50 8B 74 24 4C 52 50 56 8D 4C 24 18 C7 44 24 50 03 00 00 00 E8 ?? ?? ?? ?? 8B 4C 24 30 8B 7C 24 34 33 C0 F3 AB 8B 4C }
	condition:
		any of them
}

rule CryptoPP_modulo_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "CryptoPP modulo"
	strings:
		$c0 = { 83 EC 20 53 55 8B 6C 24 2C 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 04 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 04 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 04 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 34 33 C9 53 0B CA 55 }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 56 57 8B F1 33 FF 8D 4C 24 20 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 0C 89 7C 24 3C E8 ?? ?? ?? ?? 8B 44 24 48 8D 4C 24 0C 50 56 8D 54 24 28 51 52 C6 44 24 4C 01 E8 ?? ?? ?? ?? 8B 74 24 54 83 C4 10 8D 44 24 20 8B CE 50 E8 ?? ?? ?? ?? 8B 7C 24 18 8B 4C 24 14 8B D7 33 C0 F3 AB 52 E8 ?? ?? ?? ?? 8B 7C 24 30 8B 4C 24 2C 8B D7 33 C0 C7 44 24 10 ?? ?? ?? ?? 52 F3 AB E8 ?? ?? ?? ?? 8B 4C 24 3C 83 C4 08 8B C6 64 89 }
		$c2 = { 83 EC 24 53 55 8B 6C 24 30 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 0C 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 0C 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 0C 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 38 33 C9 53 0B CA 55 }
		$c3 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 1C 56 57 8B F1 33 FF 8D 4C 24 0C 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 18 89 7C 24 2C E8 ?? ?? ?? ?? 8B 44 24 38 8D 4C 24 18 50 56 8D 54 24 14 51 52 C6 44 24 3C 01 E8 ?? ?? ?? ?? 8B 74 24 44 83 C4 10 8D 44 24 0C 8B CE 50 E8 ?? ?? ?? ?? 8B 4C 24 18 8B 7C 24 1C 33 C0 F3 AB 8B 4C 24 1C 51 E8 ?? ?? ?? ?? 8B 4C 24 10 8B 7C 24 14 33 C0 F3 AB 8B 54 24 14 52 E8 ?? ?? ?? ?? 8B 4C 24 2C 83 C4 08 8B C6 64 89 0D 00 00 00 }
	condition:
		any of them
}

rule FGint_MontgomeryModExp_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint MontgomeryModExp"
	strings:
		$c0 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
		$c1 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
		$c2 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 ?? E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
		$c3 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 D0 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 47 4C 47 00 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 D0 E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 02 02 00 00 }
	condition:
		any of them
}

rule FGint_FGIntModExp_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntModExp"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D ?? 8B F1 89 55 ?? 8B D8 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 46 04 8B 40 04 83 E0 01 83 F8 01 75 0F 57 8B CE 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? EB ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 F4 8B C3 E8 ?? ?? ?? ?? 8B 45 }
	condition:
		$c0
}

rule FGint_MulByInt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MulByInt"
	strings:
		$c0 = { 53 56 57 55 83 C4 E8 89 4C 24 04 8B EA 89 04 24 8B 04 24 8B 40 04 8B 00 89 44 24 08 8B 44 24 08 83 C0 02 50 8D 45 04 B9 01 00 00 00 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 04 33 F6 8B 7C 24 08 85 FF 76 6D BB 01 00 00 00 8B 04 24 8B 40 04 8B 04 98 33 D2 89 44 24 10 89 54 24 14 8B 44 24 04 33 D2 52 50 8B 44 24 18 8B 54 24 1C ?? ?? ?? ?? ?? 89 44 24 10 89 54 24 14 8B C6 33 D2 03 44 24 10 13 54 24 14 89 44 24 10 89 54 24 14 8B 44 24 10 25 FF FF FF 7F 8B 55 04 89 04 9A 8B 44 24 10 8B 54 24 14 0F AC D0 1F C1 EA 1F 8B F0 43 4F 75 98 }
	condition:
		$c0
}

rule FGint_DivMod_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntDivMod"
	strings:
		$c0 = { 55 8B EC 83 C4 BC 53 56 57 8B F1 89 55 F8 89 45 FC 8B 5D 08 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 FC 8A 00 88 45 D7 8B 45 F8 8A 00 88 45 D6 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B D3 8B 45 FC E8 ?? ?? ?? ?? 8D 55 E0 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 F8 8B 45 FC }
	condition:
		$c0
}

rule FGint_FGIntDestroy_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntDestroy"
	strings:
		$c0 = { 53 8B D8 8D 43 04 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$c0
}

rule FGint_Base10StringToGInt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint Base10StringToGInt"
	strings:
		$c0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 8B DA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC ?? ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC ?? ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? EB 18 C6 45 EB 01 EB 12 8D 45 FC }
		$c1 = { 55 8B EC 83 C4 D8 53 56 57 33 C9 89 4D D8 89 4D DC 89 4D E0 89 4D E4 89 4D EC 8B DA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 0F 42 45 00 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC E8 ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 45 E4 BA 28 42 45 00 E8 ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? EB 18 C6 45 EB 01 }
		$c2 = { 55 8B EC 83 C4 D8 53 56 33 C9 89 4D D8 89 4D DC 89 4D E0 89 4D F8 89 4D F4 8B DA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 A6 32 47 00 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 8B 45 FC 0F B6 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC E8 ?? ?? ?? ?? 48 7F D3 8D 45 E0 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 45 E0 BA BC 32 47 00 E8 ?? ?? ?? ?? 75 18 C6 45 E9 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? EB 18 C6 45 E9 01 }

	condition:
		any of them
}

rule FGint_ConvertBase256to64_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertBase256to64"
	strings:
		$c0 = { 55 8B EC 81 C4 EC FB FF FF 53 56 57 33 C9 89 8D EC FB FF FF 89 8D F0 FB FF FF 89 4D F8 8B FA 89 45 FC B9 00 01 00 00 8D 85 F4 FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 F4 FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 7E 2F BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F4 FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E5 EB }
	condition:
		$c0
}

rule FGint_ConvertHexStringToBase256String_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint ConvertHexStringToBase256String"
	strings:
		$c0 = { 55 8B EC 83 C4 F0 53 56 33 C9 89 4D F0 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? D1 F8 79 03 83 D0 00 85 C0 7E 5F 89 45 F4 BE 01 00 00 00 8B C6 03 C0 8B 55 FC 8A 54 02 FF 8B 4D FC 8A 44 01 FE 3C 3A 73 0A 8B D8 80 EB 30 C1 E3 04 EB 08 8B D8 80 EB 37 C1 E3 04 80 FA 3A 73 07 80 EA 30 0A DA EB 05 80 EA 37 0A DA 8D 45 F0 8B D3 }
	condition:
		$c0
}

rule FGint_Base256StringToGInt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint Base256StringToGInt"
	strings:
		$c0 = { 55 8B EC 81 C4 F8 FB FF FF 53 56 57 33 C9 89 4D F8 8B FA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? B9 00 01 00 00 8D 85 F8 FB FF FF 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F8 ?? ?? ?? ?? ?? 8D 85 F8 FB FF FF BA FF 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC ?? ?? ?? ?? ?? 8B D8 85 DB 7E 34 BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F8 FB FF FF ?? ?? ?? ?? ?? 46 4B 75 E5 EB 12 8D 45 F8 B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 F8 80 38 30 75 0F }
	condition:
		$c0
}

rule FGint_FGIntToBase256String_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint FGIntToBase256String"
	strings:
		$c0 = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4B 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 8A 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 4B 75 B5 }
		$c1 = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC 85 C0 74 05 83 E8 04 8B 00 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4C 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 0F B6 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 }
	condition:
		any of them
}

rule FGint_ConvertBase256StringToHexString_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertBase256StringToHexString"
	strings:
		$c0 = { 55 8B EC 33 C9 51 51 51 51 51 51 53 56 57 8B F2 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C6 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B F8 85 FF 0F 8E AB 00 00 00 C7 45 F8 01 00 00 00 8B 45 FC 8B 55 F8 8A 5C 10 FF 33 C0 8A C3 C1 E8 04 83 F8 0A 73 1E 8D 45 F4 33 D2 8A D3 C1 EA 04 83 C2 30 E8 ?? ?? ?? ?? 8B 55 F4 8B C6 E8 ?? ?? ?? ?? EB 1C 8D 45 F0 33 D2 8A D3 C1 EA 04 83 C2 37 E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8B C3 24 0F 3C 0A 73 22 8D 45 EC 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 30 E8 ?? ?? ?? ?? 8B 55 EC 8B C6 E8 ?? ?? ?? ?? EB 20 8D 45 E8 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 37 }
	condition:
		$c0
}


rule FGint_PGPConvertBase256to64_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint PGPConvertBase256to64"
	strings:
		$c0 = { 55 8B EC 81 C4 E8 FB FF FF 53 56 57 33 C9 89 8D E8 FB FF FF 89 4D F8 89 4D F4 89 4D F0 8B FA 89 45 FC B9 00 01 00 00 8D 85 EC FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 EC FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC 8B 00 E8 ?? ?? ?? ?? 8B D8 85 DB 7E 22 BE 01 00 00 00 8D 45 F8 8B 55 FC 8B 12 0F B6 54 32 FF 8B 94 95 EC FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E3 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 85 D2 75 0A 8D 45 F0 E8 ?? ?? ?? ?? EB 4B 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 83 FA 04 75 1C 8D 45 F8 BA 4C 33 40 00 E8 ?? ?? ?? ?? 8D 45 F0 BA 58 33 40 00 E8 ?? ?? ?? ?? EB 1A 8D 45 F8 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B D8 85 DB 7E 57 8D 45 F4 50 B9 06 00 00 00 BA 01 00 00 00 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 EC 8B 55 F4 E8 ?? ?? ?? ?? 8D 85 E8 FB FF FF 8B 55 EC 8A 92 ?? ?? ?? ?? E8 }
	condition:
		$c0
}


rule FGint_RSAEncrypt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint RSAEncrypt"
	strings:
		$c0 = { 55 8B EC 83 C4 D0 53 56 57 33 DB 89 5D D0 89 5D DC 89 5D D8 89 5D D4 8B F9 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 DC 8B C7 E8 ?? ?? ?? ?? 8B 45 DC E8 ?? ?? ?? ?? 8B D8 8D 55 DC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 DC 8B 4D DC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F3 4E EB 10 }
	condition:
		$c0
}

rule FGint_RsaDecrypt_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "FGint RsaDecrypt"
	strings:
		$c0 = { 55 8B EC 83 C4 A0 53 56 57 33 DB 89 5D A0 89 5D A4 89 5D A8 89 5D B4 89 5D B0 89 5D AC 89 4D F8 8B FA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 }
	condition:
		$c0
}

rule FGint_RSAVerify_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "FGint RSAVerify"
	strings:
		$c0 = { 55 8B EC 83 C4 E0 53 56 8B F1 89 55 F8 89 45 FC 8B 5D 0C 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E8 8B 45 F8 E8 ?? ?? ?? ?? 8D 55 F0 8B 45 FC E8 ?? ?? ?? ?? 8D 4D E0 8B D3 8D 45 F0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 50 8B CB 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E8 E8 ?? ?? ?? ?? 3C 02 8B 45 08 0F 94 00 8D 45 E8 E8 ?? ?? ?? ?? 8D 45 F0 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? B9 03 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 BA 02 00 00 00 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule FGint_FindPrimeGoodCurveAndPoint_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint FindPrimeGoodCurveAndPoint"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 F4 53 56 57 33 DB 89 5D F4 89 4D FC 8B FA 8B F0 33 C0 55 }
	condition:
		$c0
}

rule FGint_ECElGamalEncrypt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint ECElGamalEncrypt"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 81 C4 3C FF FF FF 53 56 57 33 DB 89 5D D8 89 5D D4 89 5D D0 8B 75 10 8D 7D 8C A5 A5 A5 A5 A5 8B 75 14 8D 7D A0 A5 A5 A5 A5 A5 8B 75 18 8D 7D DC A5 A5 8B 75 1C 8D 7D E4 A5 A5 8B F1 8D 7D EC A5 A5 8B F2 8D 7D F4 A5 A5 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 8C 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 78 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 64 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 50 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 3C FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 7D CF }
		$c1 = { 55 8B EC 83 C4 A8 53 56 57 33 DB 89 5D A8 89 5D AC 89 5D BC 89 5D B8 89 5D B4 89 4D F4 89 55 F8 89 45 FC 8B 75 0C 8B 45 FC E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 71 14 41 00 64 FF 30 64 89 20 8D 55 BC 8B C6 E8 ?? ?? ?? ?? 8B 45 BC E8 ?? ?? ?? ?? 8B D8 8D 55 BC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 BC 8B 4D BC BA 8C 14 41 00 E8 ?? ?? ?? ?? 8B FB 4F EB 10 8D 45 BC 8B 4D BC BA 98 14 41 00 E8 ?? ?? ?? ?? 8B 45 BC }
	condition:
		$c0 or $c1
}

rule FGint_ECAddPoints_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint ECAddPoints"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 A8 53 56 57 8B 75 0C 8D 7D F0 A5 A5 8B F1 8D 7D F8 A5 A5 8B F2 8D 7D A8 A5 A5 A5 A5 A5 8B F0 8D 7D BC A5 A5 A5 A5 A5 8B 5D 08 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 }
	condition:
		$c0
}

rule FGint_ECPointKMultiple_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint ECPointKMultiple"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 BC 53 56 57 33 DB 89 5D E4 8B 75 0C 8D 7D E8 A5 A5 8B F1 8D 7D F0 A5 A5 8B F2 8D 7D F8 A5 A5 8B F0 8D 7D D0 A5 A5 A5 A5 A5 8B 5D 08 8D 45 D0 8B 15 ?? ?? ?? 00 E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 }
	condition:
		$c0
}

rule FGint_ECPointDestroy_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint ECPointDestroy"
		version = "0.1"
	strings:
		$c0 = { 53 8B D8 8B C3 E8 ?? ?? ?? ?? 8D 43 08 E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$c0
}

rule FGint_DSAPrimeSearch_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSAPrimeSearch"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 DC 53 56 8B DA 8B F0 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 4D F8 8B D6 8B C6 E8 ?? ?? ?? ?? 8D 4D E8 8B D6 8B C3 E8 ?? ?? ?? ?? 8D 55 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D E0 8D 55 E8 8B C3 E8 ?? ?? ?? ?? 8D 45 E8 E8 ?? ?? ?? ?? 8D 4D E8 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 F0 E8 ?? ?? ?? ?? 8B 45 EC 8B 40 04 83 E0 01 85 C0 75 18 8D 4D E0 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 ?? ?? ?? ?? 8B D3 8D 45 E8 E8 ?? ?? ?? ?? C6 45 DF 00 EB 26 8D 4D E8 8D 55 F8 8B C3 E8 ?? ?? ?? ?? 8B D3 8D 45 E8 E8 ?? ?? ?? ?? 8D 4D DF 8B C3 BA 05 00 00 00 E8 ?? ?? ?? ?? 80 7D DF 00 74 D4 8D 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? B9 04 00 00 00 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule FGint_DSASign_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSASign"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 CC 53 56 57 89 4D FC 8B DA 8B F8 8B 75 14 8B 45 10 E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F4 50 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 4D D4 8B D3 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8B C6 E8 ?? ?? ?? ?? 8D 55 EC 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 D4 8B 45 18 E8 ?? ?? ?? ?? 8D 4D DC 8D 55 E4 8D 45 EC E8 ?? ?? ?? ?? 8D 45 EC E8 ?? ?? ?? ?? 8D 45 E4 E8 ?? ?? ?? ?? 8D 45 CC 50 8B CB 8D 55 DC 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 DC E8 ?? ?? ?? ?? 8B 55 0C 8D 45 D4 E8 ?? ?? ?? ?? 8B 55 08 8D 45 CC E8 ?? ?? ?? ?? 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 CC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? B9 06 00 00 00 E8 }
	condition:
		$c0
}

rule FGint_DSAVerify_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSAVerify"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 B4 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 8B 45 14 E8 ?? ?? ?? ?? 8B 45 10 E8 ?? ?? ?? ?? 8B 45 0C E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 CC 8B 45 0C E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8D 45 CC E8 ?? ?? ?? ?? 8D 55 C4 8B 45 14 E8 ?? ?? ?? ?? 8D 45 EC 50 8B CB 8D 55 F4 8D 45 C4 E8 ?? ?? ?? ?? 8D 45 C4 E8 ?? ?? ?? ?? 8D 55 D4 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 F4 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 C4 50 8B CE 8D 55 EC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 BC 50 8B CE 8D 55 E4 8B 45 18 E8 ?? ?? ?? ?? 8D 45 B4 50 8B CE 8D 55 BC 8D 45 C4 E8 ?? ?? ?? ?? 8D 45 C4 E8 }
	condition:
		$c0
}


rule DES_Long_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [long]"
	strings:
		$c0 = { 10 80 10 40 00 00 00 00 00 80 10 00 00 00 10 40 10 00 00 40 10 80 00 00 00 80 00 40 00 80 10 00 00 80 00 00 10 00 10 40 10 00 00 00 00 80 00 40 10 00 10 00 00 80 10 40 00 00 10 40 10 00 00 00 }
	condition:
		$c0
}

rule DES_sbox_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [sbox]"
	strings:
		$c0 = { 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 }
	condition:
		$c0
}

rule DES_pbox_long_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [pbox] [long]"
	strings:
		$c0 = { 0F 00 00 00 06 00 00 00 13 00 00 00 14 00 00 00 1C 00 00 00 0B 00 00 00 1B 00 00 00 10 00 00 00 00 00 00 00 0E 00 00 00 16 00 00 00 19 00 00 00 04 00 00 00 11 00 00 00 1E 00 00 00 09 00 00 00 01 00 00 00 07 00 00 00 17 00 00 00 0D 00 00 00 1F 00 00 00 1A 00 00 00 02 00 00 00 08 00 00 00 12 00 00 00 0C 00 00 00 1D 00 00 00 05 00 00 00 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp2_mont_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp2_mont"
	strings:
		$c0 = { B8 30 05 00 00 E8 ?? ?? ?? ?? 8B 84 24 48 05 00 00 53 33 DB 56 8B 08 57 89 5C 24 24 89 5C 24 30 8A 01 89 5C 24 28 A8 01 89 5C 24 0C 75 24 68 89 00 00 00 68 ?? ?? ?? ?? 6A 66 6A 76 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 30 05 00 00 C3 8B 94 24 48 05 00 00 52 E8 ?? ?? ?? ?? 8B F0 8B 84 24 54 05 00 00 50 E8 ?? ?? ?? ?? 83 C4 08 3B F3 8B F8 75 20 3B FB 75 1C 8B 8C 24 40 05 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 30 05 00 00 C3 3B F7 89 74 24 18 7F 04 89 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_mont_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_mont"
	strings:
		$c0 = { B8 A0 02 00 00 E8 ?? ?? ?? ?? 53 56 57 8B BC 24 BC 02 00 00 33 F6 8B 07 89 74 24 24 89 74 24 20 89 74 24 0C F6 00 01 75 24 68 72 01 00 00 68 ?? ?? ?? ?? 6A 66 6A 6D 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 A0 02 00 00 C3 8B 8C 24 B8 02 00 00 51 E8 ?? ?? ?? ?? 8B D8 83 C4 04 3B DE 89 5C 24 18 75 1C 8B 94 24 B0 02 00 00 6A 01 52 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 A0 02 00 00 C3 55 8B AC 24 C4 02 00 00 55 E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8B F0 55 89 74 24 24 E8 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_recp_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_recp"
	strings:
		$c0 = { B8 C8 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 D4 02 00 00 55 56 33 F6 50 89 74 24 1C 89 74 24 18 E8 ?? ?? ?? ?? 8B E8 83 C4 04 3B EE 89 6C 24 0C 75 1B 8B 8C 24 D4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 C8 02 00 00 C3 53 57 8B BC 24 EC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DE 0F 84 E7 02 00 00 8D 54 24 24 52 E8 ?? ?? ?? ?? 8B B4 24 EC 02 00 00 83 C4 04 8B 46 0C 85 C0 74 32 56 53 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 BA 02 00 00 57 8D 44 24 28 53 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_simple_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_simple"
	strings:
		$c0 = { B8 98 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 A4 02 00 00 55 56 33 ED 50 89 6C 24 1C 89 6C 24 18 E8 ?? ?? ?? ?? 8B F0 83 C4 04 3B F5 89 74 24 0C 75 1B 8B 8C 24 A4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 98 02 00 00 C3 53 57 8B BC 24 BC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DD 0F 84 71 02 00 00 8D 54 24 28 52 E8 ?? ?? ?? ?? 8B AC 24 BC 02 00 00 8B 84 24 B4 02 00 00 57 55 8D 4C 24 34 50 51 C7 44 24 30 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_inverse_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_inverse"
	strings:
		$c0 = { B8 18 00 00 00 E8 ?? ?? ?? ?? 53 55 56 57 8B 7C 24 38 33 C0 57 89 44 24 20 89 44 24 24 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 57 89 44 24 1C E8 ?? ?? ?? ?? 57 8B F0 E8 ?? ?? ?? ?? 57 89 44 24 28 E8 ?? ?? ?? ?? 57 8B E8 E8 ?? ?? ?? ?? 57 8B D8 E8 ?? ?? ?? ?? 8B F8 8B 44 24 54 50 89 7C 24 38 E8 ?? ?? ?? ?? 83 C4 20 89 44 24 24 85 C0 8B 44 24 2C 0F 84 78 05 00 00 85 C0 75 05 E8 ?? ?? ?? ?? 85 C0 89 44 24 1C 0F 84 63 05 00 00 8B 4C 24 14 6A 01 51 E8 ?? ?? ?? ?? 6A 00 57 E8 }
	condition:
		$c0
}

rule OpenSSL_DSA_MITRE___T1032_T1022 {
		meta:
		author="_pusher_"
		date="2016-08"
	strings:
		$a0 = "bignum_data" wide ascii nocase
		$a1 = "DSA_METHOD" wide ascii nocase
		$a2 = "PDSA" wide ascii nocase
		$a3 = "dsa_mod_exp" wide ascii nocase
		$a4 = "bn_mod_exp" wide ascii nocase
		$a5 = "dsa_do_verify" wide ascii nocase
		$a6 = "dsa_sign_setup" wide ascii nocase
		$a7 = "dsa_do_sign" wide ascii nocase
		$a8 = "dsa_paramgen" wide ascii nocase
		$a9 = "BN_MONT_CTX" wide ascii nocase
	condition:
		7 of ($a*)
}

rule FGint_RsaSign_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "FGint RsaSign"
	strings:
		$c0 = { 55 8B EC 83 C4 B8 53 56 57 89 4D F8 8B FA 89 45 FC 8B 75 0C 8B 5D 10 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 }
	condition:
		$c0
}


rule LockBox_RsaEncryptFile_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "LockBox RsaEncryptFile"
	strings:
		$c0 = { 55 8B EC 83 C4 F8 53 56 8B F1 8B DA 6A 20 8B C8 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 FC 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 68 FF FF 00 00 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8A 45 08 50 8B CE 8B 55 F8 8B 45 FC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule LockBox_DecryptRsaEx_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "LockBox DecryptRsaEx"
	strings:
		$c0 = { 55 8B EC 83 C4 F4 53 56 57 89 4D F8 89 55 FC 8B D8 33 C0 8A 43 04 0F B7 34 45 ?? ?? ?? ?? 0F B7 3C 45 ?? ?? ?? ?? 8B CE B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 FC 8B CE 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 B1 02 8B D3 8B 45 F4 E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B C7 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 8B C8 8B 55 F8 8B 45 F4 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 }
	condition:
		$c0
}

rule LockBox_EncryptRsaEx_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "LockBox EncryptRsaEx"
	strings:
		$c0 = { 55 8B EC 83 C4 F8 53 56 57 89 4D FC 8B FA 8B F0 33 C0 8A 46 04 0F B7 1C 45 ?? ?? ?? ?? 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B D7 8B 4D 08 8B 45 F8 E8 ?? ?? ?? ?? 6A 01 B1 02 8B D6 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 3B C3 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B C8 8B 55 FC 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 }
	condition:
		$c0
}

rule LockBox_TlbRsaKey_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "LockBox TlbRsaKey"
	strings:
		$c0 = { 53 56 84 D2 74 08 83 C4 F0 E8 ?? ?? ?? ?? 8B DA 8B F0 33 D2 8B C6 E8 ?? ?? ?? ?? 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 0C 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 10 8B C6 84 DB 74 0F E8 ?? ?? ?? ?? 64 8F 05 00 00 00 00 83 C4 0C 8B C6 5E 5B C3 }
	condition:
		$c0
}

rule BigDig_bpInit_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig bpInit"
	strings:
		$c0 = { 56 8B 74 24 0C 6A 04 56 E8 ?? ?? ?? ?? 8B C8 8B 44 24 10 83 C4 08 85 C9 89 08 75 04 33 C0 5E C3 89 70 08 C7 40 04 00 00 00 00 5E C3 }
	condition:
		$c0
}

rule BigDig_mpModExp_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig mpModExp"
	strings:
		$c0 = { 56 8B 74 24 18 85 F6 75 05 83 C8 FF 5E C3 53 55 8B 6C 24 18 57 56 55 E8 ?? ?? ?? ?? 8B D8 83 C4 08 BF 00 00 00 80 8B 44 9D FC 85 C7 75 04 D1 EF 75 F8 83 FF 01 75 08 BF 00 00 00 80 4B EB 02 D1 EF 8B 44 24 18 56 8B 74 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 4F 8D 6C 9D FC 8B 4C 24 24 8B 54 24 20 51 52 56 56 56 E8 ?? ?? ?? ?? 8B 45 00 83 C4 14 85 C7 74 19 8B 44 24 24 8B 4C 24 20 8B 54 24 18 50 51 52 56 56 E8 ?? ?? ?? ?? 83 C4 14 83 FF 01 75 0B 4B BF 00 00 00 80 83 ED 04 EB }
	condition:
		$c0
}

rule BigDig_mpModInv_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig mpModInv"
	strings:
		$c0 = { 81 EC 2C 07 00 00 8D 84 24 CC 00 00 00 53 56 8B B4 24 44 07 00 00 57 56 6A 01 50 E8 ?? ?? ?? ?? 8B 8C 24 4C 07 00 00 56 8D 94 24 80 02 00 00 51 52 E8 ?? ?? ?? ?? 8D 84 24 BC 01 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 64 07 00 00 56 8D 4C 24 30 53 51 E8 ?? ?? ?? ?? 8D 54 24 38 56 52 BF 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 34 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 78 02 00 00 56 8D 94 24 48 03 00 00 51 8D 84 24 18 04 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 BC 01 00 00 56 8D 94 }
	condition:
		$c0
}

rule BigDig_mpModMult_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig mpModMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 98 01 00 00 8D 54 24 00 56 8B B4 24 B0 01 00 00 57 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 C0 01 00 00 8B 94 24 B4 01 00 00 8D 3C 36 56 50 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 57 50 E8 ?? ?? ?? ?? 83 C4 2C 33 C0 5F 5E 81 C4 98 01 00 00 C3 }
	condition:
		$c0
}

rule BigDig_mpModulo_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig mpModulo"
	strings:
		$c0 = { 8B 44 24 10 81 EC 30 03 00 00 8B 8C 24 38 03 00 00 8D 54 24 00 56 8B B4 24 40 03 00 00 57 8B BC 24 4C 03 00 00 57 50 56 51 8D 84 24 B0 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 94 24 54 03 00 00 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 CC 01 00 00 56 51 E8 ?? ?? ?? ?? 83 C4 34 33 C0 5F 5E 81 C4 30 03 00 00 C3 }
	condition:
		$c0
}

rule BigDig_spModExpB_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig spModExpB"
	strings:
		$c0 = { 53 8B 5C 24 10 55 56 BE 00 00 00 80 85 F3 75 04 D1 EE 75 F8 8B 6C 24 14 8B C5 D1 EE 89 44 24 18 74 48 57 8B 7C 24 20 EB 04 8B 44 24 1C 57 50 50 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 F3 74 14 8B 4C 24 1C 57 55 8D 54 24 24 51 52 E8 ?? ?? ?? ?? 83 C4 10 D1 EE 75 D0 8B 44 24 14 8B 4C 24 1C 5F 5E 89 08 5D 33 C0 5B C3 8B 54 24 10 5E 5D 5B 89 02 33 C0 C3 }
	condition:
		$c0
}

rule BigDig_spModInv_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig spModInv"
	strings:
		$c0 = { 51 8B 4C 24 10 55 56 BD 01 00 00 00 33 F6 57 8B 7C 24 18 89 6C 24 0C 85 C9 74 42 53 8B C7 33 D2 F7 F1 8B C7 8B F9 8B DA 33 D2 F7 F1 8B CB 0F AF C6 03 C5 8B EE 8B F0 8B 44 24 10 F7 D8 85 DB 89 44 24 10 75 D7 85 C0 5B 7D 13 8B 44 24 1C 8B 4C 24 14 2B C5 5F 89 01 5E 33 C0 5D 59 C3 8B 54 24 14 5F 5E 33 C0 89 2A 5D 59 C3 }
	condition:
		$c0
}

rule BigDig_spModMult_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "BigDig spModMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 83 EC 08 8D 54 24 00 50 51 52 E8 ?? ?? ?? ?? 8B 44 24 24 6A 02 8D 4C 24 10 50 51 E8 ?? ?? ?? ?? 8B 54 24 24 89 02 33 C0 83 C4 20 C3 }
	condition:
		$c0
}

rule CryptoPP_ApplyFunction_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "CryptoPP ApplyFunction"
	strings:
		$c0 = { 51 8D 41 E4 56 8B 74 24 0C 83 C1 F0 50 51 8B 4C 24 18 C7 44 24 0C 00 00 00 00 51 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5E 59 C2 08 00 }
		$c1 = { 51 53 56 8B F1 57 6A 00 C7 44 24 10 00 00 00 00 8B 46 04 8B 48 04 8B 5C 31 04 8D 7C 31 04 E8 ?? ?? ?? ?? 50 8B CF FF 53 10 8B 44 24 18 8D 56 08 83 C6 1C 52 56 8B 74 24 1C 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5F 5E 5B 59 C2 08 00 }
	condition:
		any of them
}

rule CryptoPP_RsaFunction_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "CryptoPP RsaFunction"
	strings:
		$c0 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 9C 00 00 00 8B 84 24 B0 00 00 00 53 55 56 33 ED 8B F1 57 3B C5 89 B4 24 A8 00 00 00 89 6C 24 10 BF 01 00 00 00 74 18 C7 06 ?? ?? ?? ?? C7 46 20 ?? ?? ?? ?? 89 7C 24 10 89 AC 24 B4 00 00 00 8D 4E 04 E8 ?? ?? ?? ?? 8D 4E 10 89 BC 24 B4 00 00 00 E8 ?? ?? ?? ?? 8B 06 BB ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 48 04 C7 04 31 ?? ?? ?? ?? 8B 16 8B 42 04 8B 54 24 10 83 CA 02 8D 48 E0 89 54 24 10 89 4C 30 FC 89 5C 24 18 89 7C }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 1C 53 8B 5C 24 1C 56 8B F1 57 33 C9 89 74 24 10 3B C1 89 4C 24 0C 74 7B C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 3B D9 75 06 89 4C 24 28 EB 0E 8B 43 04 8B 50 0C 8D 44 1A 04 89 44 24 28 8B 56 3C C7 44 24 0C 07 00 00 00 8B 42 04 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C C7 46 38 ?? ?? ?? ?? 8B 42 04 C7 44 30 3C }
		$c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 18 56 8B F1 57 85 C0 89 74 24 0C C7 44 24 08 00 00 00 00 74 63 C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 8B 46 3C C7 44 24 08 07 00 00 00 8B 48 04 C7 44 31 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 4E 3C C7 46 38 ?? ?? ?? ?? 8B 51 04 C7 44 32 3C ?? ?? ?? ?? 8B 46 3C 8B 48 08 C7 44 31 3C ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 8D 7E 04 6A 00 8B CF }
	condition:
		any of them
}

rule CryptoPP_Integer_constructor_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "CryptoPP Integer constructor"
	strings:
		$c0 = { 8B 44 24 08 56 83 F8 08 8B F1 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 4C 24 0C 89 46 04 C7 46 08 00 00 00 00 89 08 8B 0E 8B 46 04 83 C4 04 49 74 0F 57 8D 78 04 33 C0 F3 AB 8B C6 5F 5E C2 08 00 8B C6 5E C2 08 00 }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 89 74 24 04 C7 06 ?? ?? ?? ?? 6A 08 C7 44 24 14 00 00 00 00 C7 46 08 02 00 00 00 E8 ?? ?? ?? ?? 89 46 0C C7 46 10 00 00 00 00 C7 06 ?? ?? ?? ?? 8B 46 0C 83 C4 04 C7 40 04 00 00 00 00 8B 4E 0C 8B C6 5E C7 01 00 00 00 00 8B 4C 24 04 64 89 0D 00 00 00 00 83 C4 10 C3 }
		$c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 57 89 74 24 08 C7 06 ?? ?? ?? ?? 8B 7C 24 1C C7 44 24 14 00 00 00 00 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 85 D2 89 56 08 76 12 8D 04 95 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 04 EB 02 33 C0 89 46 0C 8B 4F 10 89 4E 10 }
		$c3 = { 56 57 8B 7C 24 0C 8B F1 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 16 89 46 04 8B 4F 08 83 C4 04 89 4E 08 8B 4F 04 85 D2 76 0D 2B C8 8B 3C 01 89 38 83 C0 04 4A 75 F5 8B C6 5F 5E C2 04 00 }
	condition:
		any of them
}

rule RijnDael_AES_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "RijnDael AES"
		date = "2016-06"
	strings:
		$c0 = { A5 63 63 C6 84 7C 7C F8 }
	condition:
		$c0
}

rule RijnDael_AES_CHAR_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "RijnDael AES (check2) [char]"
		date = "2016-06"
	strings:
		$c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
	condition:
		$c0
}

rule RijnDael_AES_CHAR_inv_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "RijnDael AES S-inv [char]"
		//needs improvement
		date = "2016-07"
	strings:
		$c0 = { 48 38 47 00 88 17 33 D2 8A 56 0D 8A 92 48 38 47 00 88 57 01 33 D2 8A 56 0A 8A 92 48 38 47 00 88 57 02 33 D2 8A 56 07 8A 92 48 38 47 00 88 57 03 33 D2 8A 56 04 8A 92 }
	condition:
		$c0
}

rule RijnDael_AES_LONG_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "RijnDael AES"
		date = "2016-06"
	strings:
		$c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
	condition:
		$c0
}

rule RsaRef2_NN_modExp_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modExp"
	strings:
		$c0 = { 81 EC 1C 02 00 00 53 55 56 8B B4 24 30 02 00 00 57 8B BC 24 44 02 00 00 57 8D 84 24 A4 00 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 4C 02 00 00 57 53 8D 8C 24 B4 00 00 00 56 8D 94 24 3C 01 00 00 51 52 E8 ?? ?? ?? ?? 57 53 8D 84 24 4C 01 00 00 56 8D 8C 24 D4 01 00 00 50 51 E8 ?? ?? ?? ?? 8D 54 24 50 57 52 E8 ?? ?? ?? ?? 8B 84 24 78 02 00 00 8B B4 24 74 02 00 00 50 56 C7 44 24 60 01 00 00 00 E8 ?? ?? ?? ?? 8D 48 FF 83 C4 44 8B E9 89 4C 24 18 85 ED 0F 8C AF 00 00 00 8D 34 AE 89 74 24 }
	condition:
		any of them
}

rule RsaRef2_NN_modInv_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modInv"
	strings:
		$c0 = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 84 24 ?? 00 00 00 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 BC 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 4C 24 2C 53 51 E8 ?? ?? ?? ?? 8D 54 24 34 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 2C 01 }
	condition:
		$c0
}

rule RsaRef2_NN_modMult_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 68 08 01 00 00 8D 4C 24 2C 6A 00 51 E8 ?? ?? ?? ?? 83 C4 30 5E 81 C4 08 01 00 00 C3 }
	condition:
		$c0
}

rule RsaRef2_RsaPrivateDecrypt_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateDecrypt"
	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8B 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6B 8A 4C 24 09 B8 02 00 00 00 3A C8 75 5E 8D 4E FF 3B C8 76 0D 8A 54 04 08 84 D2 74 05 40 3B C1 72 F3 40 3B C6 73 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A 8D 51 0B }
	condition:
		$c0
}

rule RsaRef2_RsaPrivateEncrypt_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateEncrypt"
	strings:
		$c0 = { 8B 44 24 14 8B 54 24 10 81 EC 80 00 00 00 8D 4A 0B 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 80 00 00 00 C3 8B CE B8 02 00 00 00 2B CA C6 44 24 04 00 49 C6 44 24 05 01 3B C8 76 23 53 55 8D 69 FE 57 8B CD 83 C8 FF 8B D9 8D 7C 24 12 C1 E9 02 F3 AB 8B CB 83 E1 03 F3 AA 8D 45 02 5F 5D 5B 52 8B 94 24 94 00 00 00 C6 44 04 08 00 8D 44 04 09 52 50 E8 ?? ?? ?? ?? 8B 8C 24 A4 00 00 00 8B 84 24 98 00 00 00 51 8B 8C 24 98 00 00 00 8D 54 24 14 56 52 50 51 E8 }
	condition:
		$c0
}

rule RsaRef2_RsaPublicDecrypt_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicDecrypt"
	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8E 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6E 80 7C 24 09 01 75 67 B8 02 00 00 00 8D 4E FF 3B C8 76 0D B2 FF 38 54 04 08 75 05 40 3B C1 72 F5 8A 4C 04 08 40 84 C9 75 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A }
	condition:
		$c0
}

rule RsaRef2_RsaPublicEncrypt_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicEncrypt"
	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 53 8B 9C 24 98 00 00 00 57 8B 38 83 C7 07 8D 4B 0B C1 EF 03 3B CF 76 0E 5F B8 06 04 00 00 5B 81 C4 84 00 00 00 C3 8B D7 55 2B D3 56 BE 02 00 00 00 C6 44 24 14 00 8D 6A FF C6 44 24 15 02 3B EE 76 28 8B 84 24 AC 00 00 00 8D 4C 24 13 50 6A 01 51 E8 ?? ?? ?? ?? 8A 44 24 1F 83 C4 0C 84 C0 74 E1 88 44 34 14 46 3B F5 72 D8 8B 94 24 A0 00 00 00 53 8D 44 34 19 52 50 C6 44 34 20 00 E8 ?? ?? ?? ?? 8B 8C 24 B4 00 00 00 8B 84 24 A8 00 00 00 51 8B 8C 24 A8 00 }
	condition:
		$c0
}

rule RsaEuro_NN_modInv_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaEuro NN_modInv"
	strings:
		$c0 = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 44 24 0C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 7C 24 1C E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 8C 24 B0 00 00 00 53 51 E8 ?? ?? ?? ?? 8D 94 24 B8 00 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 F8 00 00 00 8D 84 24 ?? 00 00 00 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C }
	condition:
		$c0
}

rule RsaEuro_NN_modMult_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "RsaEuro NN_modMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 83 C4 24 5E 81 C4 08 01 00 00 C3 }
	condition:
		$c0
}

rule Miracl_Big_constructor_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "Miracl Big constructor"
	strings:
		$c0 = { 56 8B F1 6A 00 E8 ?? ?? ?? ?? 83 C4 04 89 06 8B C6 5E C3 }
	condition:
		$c0
}

rule Miracl_mirvar_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "Miracl mirvar"
	strings:
		$c0 = { 56 E8 ?? ?? ?? ?? 8B 88 18 02 00 00 85 C9 74 04 33 C0 5E C3 8B 88 8C 00 00 00 85 C9 75 0E 6A 12 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5E C3 8B 80 38 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F0 83 C4 08 85 F6 75 02 5E C3 8D 46 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 08 85 C0 74 0A 56 50 E8 ?? ?? ?? ?? 83 C4 08 8B C6 5E C3 }
		$c1 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 2C 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 40 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 46 18 6A 01 8D 0C 85 0C 00 00 00 51 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B D0 8B C8 83 E2 03 2B CA 83 C1 08 89 08 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
		$c2 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 86 A4 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
	condition:
		any of them
}

rule Miracl_mirsys_init_MITRE___T1032_T1022 {
	meta:
		author = "Maxx"
		description = "Miracl mirsys init"
	strings:
		$c0 = { 53 55 57 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB A3 ?? ?? ?? ?? 3B C3 75 06 5F 5D 33 C0 5B C3 89 58 1C A1 ?? ?? ?? ?? BD 01 00 00 00 89 58 20 A1 ?? ?? ?? ?? 8B 50 1C 42 89 50 1C A1 ?? ?? ?? ?? 8B 48 1C C7 44 88 20 1D 00 00 00 8B 15 ?? ?? ?? ?? 89 9A 14 02 00 00 A1 ?? ?? ?? ?? 89 98 70 01 00 00 8B 0D ?? ?? ?? ?? 89 99 78 01 00 00 8B 15 ?? ?? ?? ?? 89 9A 98 01 00 00 A1 ?? ?? ?? ?? 89 58 14 8B 44 24 14 3B C5 0F 84 6C 05 00 00 3D 00 00 00 80 0F 87 61 05 00 00 50 E8 }
	condition:
		$c0
}

/* //gives many false positives sorry Storm Shadow
rule x509_public_key_infrastructure_cert_MITRE___T1032_T1022 {
	meta:
		desc = "X.509 PKI Certificate"
		ext = "crt"
	strings:
		$c0 = { 30 82 ?? ?? 30 82 ?? ?? }
	condition:
		$c0
}

rule pkcs8_private_key_information_syntax_standard_MITRE___T1032_T1022 {
	meta:
		desc = "Found PKCS #8: Private-Key"
		ext = "key"
	strings:
		$c0 = { 30 82 ?? ?? 02 01 00 }
	condition:
		$c0
}
*/

rule BASE64_table_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Base64 table"
		date = "2015-07"
		version = "0.1"
	strings:
		$c0 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F }
	condition:
		$c0
}

rule Delphi_Random_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { 53 31 DB 69 93 ?? ?? ?? ?? 05 84 08 08 42 89 93 ?? ?? ?? ?? F7 E2 89 D0 5B C3 }
		//x64 rad
		$c1 = { 8B 05 ?? ?? ?? ?? 69 C0 05 84 08 08 83 C0 01 89 05 ?? ?? ?? ?? 8B C9 8B C0 48 0F AF C8 48 C1 E9 20 89 C8 C3 }
	condition:
		any of them
}

rule Delphi_RandomRange_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for RandomRange function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 56 8B F2 8B D8 3B F3 7D 0E 8B C3 2B C6 E8 ?? ?? ?? ?? 03 C6 5E 5B C3 8B C6 2B C3 E8 ?? ?? ?? ?? 03 C3 5E 5B C3 }
	condition:
		$c0
}

rule Delphi_FormShow_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Form.Show function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 8B D8 B2 01 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 48 89 D9 B2 01 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		any of them
}

rule Delphi_CompareCall_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Compare string function"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 89 C6 89 D7 39 D0 0F 84 8F 00 00 00 85 F6 74 68 85 FF 74 6B 8B 46 FC 8B 57 FC 29 D0 77 02 01 C2 52 C1 EA 02 74 26 8B 0E 8B 1F 39 D9 75 58 4A 74 15 8B 4E 04 8B 5F 04 39 D9 75 4B 83 C6 08 83 C7 08 4A 75 E2 EB 06 83 C6 04 83 C7 04 5A 83 E2 03 74 22 8B 0E 8B 1F 38 D9 75 41 4A 74 17 38 FD 75 3A 4A 74 10 81 E3 00 00 FF 00 81 E1 00 00 FF 00 39 D9 75 27 01 C0 EB 23 8B 57 FC 29 D0 EB 1C 8B 46 FC 29 D0 EB 15 5A 38 D9 75 10 38 FD 75 0C C1 E9 10 C1 EB 10 38 D9 75 02 38 FD 5F 5E 5B C3 }
		//newer delphi
		$c1 = { 39 D0 74 30 85 D0 74 22 8B 48 FC 3B 4A FC 75 24 01 C9 01 C8 01 CA F7 D9 53 8B 1C 01 3B 1C 11 75 07 83 C1 04 78 F3 31 C0 5B C3}
		//x64
		$c2 = { 41 56 41 55 57 56 53 48 83 EC 20 48 89 D3 48 3B CB 75 05 48 33 C0 EB 74 48 85 C9 75 07 8B 43 FC F7 D8 EB 68 48 85 DB 75 05 8B 41 FC EB 5E 8B 79 FC 44 8B 6B FC 89 FE 41 3B F5 7E 03 44 89 EE E8 ?? ?? ?? ?? 49 89 C6 48 89 D9 E8 ?? ?? ?? ?? 48 89 C1 85 F6 7E 30 41 0F B7 06 0F B7 11 2B C2 85 C0 75 29 83 FE 01 74 1E 41 0F B7 46 02 0F B7 51 02 2B C2 85 C0 75 15 49 83 C6 04 48 83 C1 04 83 EE 02 85 F6 7F D0 90 8B C7 41 2B C5 48 83 C4 20 5B 5E 5F 41 5D 41 5E C3 }
 	condition:
		any of them
}

rule Delphi_Copy_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Copy function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 85 C0 74 2D 8B 58 FC 85 DB 74 26 4A 7C 1B 39 DA 7D 1F 29 D3 85 C9 7C 19 39 D9 7F 11 01 C2 8B 44 24 08 E8 ?? ?? ?? ?? EB 11 31 D2 EB E5 89 D9 EB EB 8B 44 24 08 E8 ?? ?? ?? ?? 5B C2 04 00 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 44 89 C0 48 33 C9 48 85 D2 74 03 8B 4A FC 83 F8 01 7D 05 48 33 C0 EB 09 83 E8 01 3B C1 7E 02 89 C8 45 85 C9 7D 05 48 33 C9 EB 0A 2B C8 41 3B C9 7E 03 44 89 C9 49 89 D8 48 63 C0 48 8D 14 42 89 C8 4C 89 C1 41 89 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		any of them
}

rule Delphi_IntToStr_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for IntToStr function"
		date = "2016-04"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 81 C4 00 FF FF FF 53 56 8B F2 8B D8 FF 75 0C FF 75 08 8D 85 00 FF FF FF E8 ?? ?? ?? ?? 8D 95 00 FF FF FF 8B C6 E8 ?? ?? ?? ?? EB 0E 8B 0E 8B C6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 E8 ?? ?? ?? ?? 33 D2 8A D3 3B C2 72 E3 5E 5B 8B E5 5D C2 08 00 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 48 85 D2 7D 10 48 89 D9 48 F7 DA 41 B0 01 E8 ?? ?? ?? ?? EB 0B 48 89 D9 4D 33 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		any of them
}


rule Delphi_StrToInt_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for StrToInt function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 56 83 C4 F4 8B D8 8B D4 8B C3 E8 ?? ?? ?? ?? 8B F0 83 3C 24 00 74 19 89 5C 24 04 C6 44 24 08 0B 8D 54 24 04 A1 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? 8B C6 83 C4 0C 5E 5B C3 }
		//x64 rad
		$c1 = { 55 56 53 48 83 EC 40 48 8B EC 48 89 CB 48 89 D9 48 8D 55 3C E8 ?? ?? ?? ?? 89 C6 83 7D 3C 00 74 1B 48 89 5D 20 C6 45 28 11 48 8B 0D ?? ?? ?? ?? 48 8D 55 20 4D 33 C0 E8 ?? ?? ?? ?? 89 F0 48 8D 65 40 5B 5E 5D C3 }
	condition:
		any of them
}

rule Delphi_DecodeDate_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DecodeDate (DecodeDateFully) function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 89 4D F4 89 55 F8 89 45 FC 8B 5D 08 FF 75 10 FF 75 0C 8D 45 E8 E8 ?? ?? ?? ?? 8B 4D EC 85 C9 7F 24 8B 45 FC 66 C7 00 00 00 8B 45 F8 66 C7 00 00 00 8B 45 F4 66 C7 00 00 00 66 C7 03 00 00 33 D2 E9 F2 00 00 00 8B C1 BE 07 00 00 00 99 F7 FE 42 66 89 13 49 66 BB 01 00 81 F9 B1 3A 02 00 7C 13 81 E9 B1 3A 02 00 66 81 C3 90 01 81 F9 B1 3A 02 00 7D ED 8D 45 F2 50 8D 45 F0 66 BA AC 8E 91 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 AC 8E 66 6B 45 F0 64 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA B5 05 E8 ?? ?? ?? ?? 66 8B 45 F0 C1 E0 02 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA 6D 01 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 6D 01 66 03 5D F0 8B C3 E8 ?? ?? ?? ?? 8B D0 33 C0 8A C2 8D 04 40 8D 34 C5 ?? ?? ?? ?? 66 B8 01 00 0F B7 C8 66 8B 4C 4E FE 66 89 4D F0 66 8B 4D F2 66 3B 4D F0 72 0B 66 8B 4D F0 66 29 4D F2 40 EB DF 8B 4D FC 66 89 19 8B 4D F8 66 89 01 66 8B 45 F2 40 8B 4D F4 66 89 01 8B C2 5E 5B 8B E5 5D C2 0C 00 }
		//x64
		$c1 = { 55 41 55 57 56 53 48 83 EC 30 48 8B EC 48 89 D3 4C 89 C6 4C 89 CF E8 ?? ?? ?? ?? 48 8B C8 48 C1 E9 20 85 C9 7F 23 66 C7 03 00 00 66 C7 06 00 00 66 C7 07 00 00 48 8B 85 80 00 00 00 66 C7 00 00 00 48 33 C0 E9 19 01 00 00 4C 8B 85 80 00 00 00 41 C7 C1 07 00 00 00 8B C1 99 41 F7 F9 66 83 C2 01 66 41 89 10 83 E9 01 66 41 BD 01 00 81 F9 B1 3A 02 00 7C 14 81 E9 B1 3A 02 00 66 41 81 C5 90 01 81 F9 B1 3A 02 00 7D EC 90 66 BA AC 8E 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E AC 8E 66 6B 45 2C 64 66 44 03 E8 0F B7 4D 2E 66 BA B5 05 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 48 0F B7 45 2C 03 C0 03 C0 66 44 03 E8 0F B7 4D 2E 66 BA 6D 01 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E 6D 01 66 44 03 6D 2C 44 89 E9 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 0F B6 D0 48 8D 14 52 48 8D 14 D1 66 B9 01 00 4C 0F B7 C1 4E 0F B7 44 42 FE 66 44 89 45 2C 4C 0F B7 45 2E 66 44 3B 45 2C 72 10 4C 0F B7 45 2C 66 44 29 45 2E 66 }
	condition:
		any of them
}


rule Unknown_Random_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 52 8B 45 08 69 15 ?? ?? ?? ?? 05 84 08 08 42 89 15 ?? ?? ?? ?? F7 E2 8B C2 5A C9 C2 04 00 }
	condition:
		$c0
}

rule VC6_Random_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-02"
	strings:
		$c0 = { A1 ?? ?? ?? ?? 69 C0 FD 43 03 00 05 C3 9E 26 00 A3 ?? ?? ?? ?? C1 F8 10 25 FF 7F 00 00 C3 }
	condition:
		$c0
}

rule VC8_Random_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-01"
		version = "0.1"
	strings:
		$c0 = { E8 ?? ?? ?? ?? 8B 48 14 69 C9 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 8B C1 C1 E8 10 25 FF 7F 00 00 C3 }
	condition:
		$c0
}

rule DCP_RIJNDAEL_Init_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DCP RijnDael Init"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 ?? ?? ?? ?? 8B D7 8B 4D FC 8B C3 8B 38 FF 57 ?? 85 F6 75 25 8D 43 38 33 C9 BA 10 00 00 00 E8 ?? ?? ?? ?? 8D 4B 38 8D 53 38 8B C3 8B 30 FF 56 ?? 8B C3 8B 10 FF 52 ?? EB 16 8D 53 38 8B C6 B9 10 00 00 00 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 52 ?? 5F 5E 5B 59 5D C2 04 00 }
	condition:
		$c0
}

rule DCP_RIJNDAEL_EncryptECB_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DCP RijnDael EncryptECB"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 55 83 C4 B4 89 0C 24 8D 74 24 08 8D 7C 24 28 80 78 30 00 75 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0A 89 0F 8B CA 83 C1 04 8B 09 8D 5F 04 89 0B 8B CA 83 C1 08 8B 09 8D 5F 08 89 0B 83 C2 0C 8B 12 8D 4F 0C 89 11 8B 50 58 83 EA 02 85 D2 0F 82 3B 01 00 00 42 89 54 24 04 33 D2 8B 0F 8B DA C1 E3 02 33 4C D8 5C 89 0E 8D 4F 04 8B 09 33 4C D8 60 8D 6E 04 89 4D 00 8D 4F 08 8B 09 33 4C D8 64 8D 6E 08 89 4D 00 8D 4F 0C 8B 09 33 4C D8 68 8D 5E 0C 89 0B 33 C9 8A 0E 8D 0C 8D }
	condition:
		$c0
}

rule DCP_BLOWFISH_Init_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DCP Blowfish Init"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 55 8B F2 8B F8 8B CF B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8B C3 8B 10 FF 52 34 8B C6 E8 ?? ?? ?? ?? 50 8B C6 E8 ?? ?? ?? ?? 8B D0 8B C3 59 8B 30 FF 56 3C 8B 43 3C 85 C0 79 03 83 C0 07 C1 F8 03 E8 ?? ?? ?? ?? 8B F0 8B D6 8B C3 8B 08 FF 51 40 8B 47 40 8B 6B 3C 3B C5 7D 0F 6A 00 8B C8 8B D6 8B C7 8B 38 FF 57 30 EB 0D 6A 00 8B D6 8B CD 8B C7 8B 38 FF 57 30 8B 53 3C 85 D2 79 03 83 C2 07 C1 FA 03 8B C6 B9 FF 00 00 00 E8 ?? ?? ?? ?? 8B 53 3C 85 D2 79 03 83 C2 07 C1 FA 03 8B C6 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5D 5F 5E 5B C3 }
	condition:
		$c0
}


rule DCP_BLOWFISH_EncryptCBC_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DCP Blowfish EncryptCBC"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 83 C4 F0 53 56 57 89 4D F8 89 55 FC 8B D8 80 7B 34 00 75 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7D 08 85 FF 79 03 83 C7 07 C1 FF 03 85 FF 7E 56 BE 01 00 00 00 6A 08 8B 45 FC 8B D6 4A C1 E2 03 03 C2 8D 4D F0 8D 53 54 E8 ?? ?? ?? ?? 8D 4D F0 8D 55 F0 8B C3 E8 ?? ?? ?? ?? 8B 55 F8 8B C6 48 C1 E0 03 03 D0 8D 45 F0 B9 08 00 00 00 E8 ?? ?? ?? ?? 8D 53 54 8D 45 F0 B9 08 00 00 00 E8 ?? ?? ?? ?? 46 4F 75 AF 8B 75 08 81 E6 07 00 00 80 79 05 4E 83 CE F8 46 85 F6 74 26 8D 4D F0 8D 53 54 8B C3 E8 ?? ?? ?? ?? 56 8B 4D F8 03 4D 08 2B CE 8B 55 FC 03 55 08 2B D6 8D 45 F0 E8 ?? ?? ?? ?? 8D 45 F0 B9 FF 00 00 00 BA 08 00 00 00 E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C2 04 00 }
	condition:
		$c0
}

rule DCP_DES_Init_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DCP Des Init"
		date = "2016-02"
	strings:
		$c0 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 FE F9 FF FF 8B D7 8B 4D FC 8B C3 8B 38 FF 57 5C 85 F6 75 25 8D 43 38 33 C9 BA 08 00 00 00 E8 F3 A9 FA FF 8D 4B 38 8D 53 38 8B C3 8B 30 FF 56 6C 8B C3 8B 10 FF 52 48 EB 16 8D 53 38 8B C6 B9 08 00 00 00 E8 6E A7 FA FF 8B C3 8B 10 FF 52 48 5F 5E 5B 59 5D C2 04 00 }
		$c1 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 EE D4 FF FF 8B D7 8B 4D FC 8B C3 8B 38 FF 57 74 85 F6 75 2B 8D 43 40 B9 FF 00 00 00 BA 08 00 00 00 E8 ?? ?? ?? ?? 8D 4B 40 8D 53 40 8B C3 8B 30 FF 96 84 00 00 00 8B C3 8B 10 FF 52 58 EB 16 8D 53 40 8B C6 B9 08 00 00 00 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 52 58 5F 5E 5B 59 5D C2 04 00 }
	condition:
		any of them
}


rule DCP_DES_EncryptECB_MITRE___T1032_T1022 {
	meta:
		author = "_pusher_"
		description = "Look for DCP Des EncryptECB"
		date = "2016-02"
	strings:
		$c0 = { 53 80 78 ?? 00 75 16 B9 ?? ?? ?? 00 B2 01 A1 ?? ?? ?? 00 E8 ?? ?? ?? FF E8 ?? ?? ?? FF 8D 58 ?? 53 E8 ?? ?? FF FF 5B C3 }
	condition:
		any of them
}


rule Obfuscated_Strings_MITRE___T1140_T1027 {
		meta:
		description = "Contains obfuscated function names"
		author = "Ivan Kwiatkowski (@JusticeRage)"
	strings:
		$a0 = { (46 | 66) 64 75 (51 | 71) 73 6E 62 (40 | 60) 65 65 73 64 72 72 } // [Gg]et[Pp]roc[Aa]ddress XOR 0x01
		$a1 = { (45 | 65) 67 76 (52 | 72) 70 6D 61 (43 | 63) 66 66 70 67 71 71 } // GetProcAddress XOR 0x02
		$a2 = { (44 | 64) 66 77 (53 | 73) 71 6C 60 (42 | 62) 67 67 71 66 70 70 } // etc...
		$a3 = { (43 | 63) 61 70 (54 | 74) 76 6B 67 (45 | 65) 60 60 76 61 77 77 }
		$a4 = { (42 | 62) 60 71 (55 | 75) 77 6A 66 (44 | 64) 61 61 77 60 76 76 }
		$a5 = { (41 | 61) 63 72 (56 | 76) 74 69 65 (47 | 67) 62 62 74 63 75 75 }
		$a6 = { (40 | 60) 62 73 (57 | 77) 75 68 64 (46 | 66) 63 63 75 62 74 74 }
		$a7 = { (4F | 6F) 6D 7C (58 | 78) 7A 67 6B (49 | 69) 6C 6C 7A 6D 7B 7B }
		$a8 = { (4E | 6E) 6C 7D (59 | 79) 7B 66 6A (48 | 68) 6D 6D 7B 6C 7A 7A }
		$a9 = { (4D | 6D) 6F 7E (5A | 7A) 78 65 69 (4B | 6B) 6E 6E 78 6F 79 79 }
		$a10 = { (4C | 6C) 6E 7F (5B | 7B) 79 64 68 (4A | 6A) 6F 6F 79 6E 78 78 }
		$a11 = { (4B | 6B) 69 78 (5C | 7C) 7E 63 6F (4D | 6D) 68 68 7E 69 7F 7F }
		$a12 = { (4A | 6A) 68 79 (5D | 7D) 7F 62 6E (4C | 6C) 69 69 7F 68 7E 7E }
		$a13 = { (49 | 69) 6B 7A (5E | 7E) 7C 61 6D (4F | 6F) 6A 6A 7C 6B 7D 7D }
		$a14 = { (48 | 68) 6A 7B (5F | 7F) 7D 60 6C (4E | 6E) 6B 6B 7D 6A 7C 7C }
		$a15 = { (57 | 77) 75 64 (40 | 60) 62 7F 73 (51 | 71) 74 74 62 75 63 63 }
		$a16 = { (56 | 76) 74 65 (41 | 61) 63 7E 72 (50 | 70) 75 75 63 74 62 62 }
		$a17 = { (55 | 75) 77 66 (42 | 62) 60 7D 71 (53 | 73) 76 76 60 77 61 61 }
		$a18 = { (54 | 74) 76 67 (43 | 63) 61 7C 70 (52 | 72) 77 77 61 76 60 60 }
		$a19 = { (53 | 73) 71 60 (44 | 64) 66 7B 77 (55 | 75) 70 70 66 71 67 67 }
		$a20 = { (52 | 72) 70 61 (45 | 65) 67 7A 76 (54 | 74) 71 71 67 70 66 66 }
		$a21 = { (51 | 71) 73 62 (46 | 66) 64 79 75 (57 | 77) 72 72 64 73 65 65 }
		$a22 = { (50 | 70) 72 63 (47 | 67) 65 78 74 (56 | 76) 73 73 65 72 64 64 }
		$a23 = { (5F | 7F) 7D 6C (48 | 68) 6A 77 7B (59 | 79) 7C 7C 6A 7D 6B 6B }
		$a24 = { (5E | 7E) 7C 6D (49 | 69) 6B 76 7A (58 | 78) 7D 7D 6B 7C 6A 6A }
		$a25 = { (5D | 7D) 7F 6E (4A | 6A) 68 75 79 (5B | 7B) 7E 7E 68 7F 69 69 }
		$a26 = { (5C | 7C) 7E 6F (4B | 6B) 69 74 78 (5A | 7A) 7F 7F 69 7E 68 68 }
		$a27 = { (5B | 7B) 79 68 (4C | 6C) 6E 73 7F (5D | 7D) 78 78 6E 79 6F 6F }
		$a28 = { (5A | 7A) 78 69 (4D | 6D) 6F 72 7E (5C | 7C) 79 79 6F 78 6E 6E }
		$a29 = { (59 | 79) 7B 6A (4E | 6E) 6C 71 7D (5F | 7F) 7A 7A 6C 7B 6D 6D }
		$a30 = { (58 | 78) 7A 6B (4F | 6F) 6D 70 7C (5E | 7E) 7B 7B 6D 7A 6C 6C }
		// XOR 0x20 removed because it toggles capitalization and causes [Gg]ET[Pp]ROC[Aa]DDRESS to match.
		$a32 = { (66 | 46) 44 55 (71 | 51) 53 4E 42 (60 | 40) 45 45 53 44 52 52 }
		$a33 = { (65 | 45) 47 56 (72 | 52) 50 4D 41 (63 | 43) 46 46 50 47 51 51 }
		$a34 = { (64 | 44) 46 57 (73 | 53) 51 4C 40 (62 | 42) 47 47 51 46 50 50 }
		$a35 = { (63 | 43) 41 50 (74 | 54) 56 4B 47 (65 | 45) 40 40 56 41 57 57 }
		$a36 = { (62 | 42) 40 51 (75 | 55) 57 4A 46 (64 | 44) 41 41 57 40 56 56 }
		$a37 = { (61 | 41) 43 52 (76 | 56) 54 49 45 (67 | 47) 42 42 54 43 55 55 }
		$a38 = { (60 | 40) 42 53 (77 | 57) 55 48 44 (66 | 46) 43 43 55 42 54 54 }
		$a39 = { (6F | 4F) 4D 5C (78 | 58) 5A 47 4B (69 | 49) 4C 4C 5A 4D 5B 5B }
		$a40 = { (6E | 4E) 4C 5D (79 | 59) 5B 46 4A (68 | 48) 4D 4D 5B 4C 5A 5A }
		$a41 = { (6D | 4D) 4F 5E (7A | 5A) 58 45 49 (6B | 4B) 4E 4E 58 4F 59 59 }
		$a42 = { (6C | 4C) 4E 5F (7B | 5B) 59 44 48 (6A | 4A) 4F 4F 59 4E 58 58 }
		$a43 = { (6B | 4B) 49 58 (7C | 5C) 5E 43 4F (6D | 4D) 48 48 5E 49 5F 5F }
		$a44 = { (6A | 4A) 48 59 (7D | 5D) 5F 42 4E (6C | 4C) 49 49 5F 48 5E 5E }
		$a45 = { (69 | 49) 4B 5A (7E | 5E) 5C 41 4D (6F | 4F) 4A 4A 5C 4B 5D 5D }
		$a46 = { (68 | 48) 4A 5B (7F | 5F) 5D 40 4C (6E | 4E) 4B 4B 5D 4A 5C 5C }
		$a47 = { (77 | 57) 55 44 (60 | 40) 42 5F 53 (71 | 51) 54 54 42 55 43 43 }
		$a48 = { (76 | 56) 54 45 (61 | 41) 43 5E 52 (70 | 50) 55 55 43 54 42 42 }
		$a49 = { (75 | 55) 57 46 (62 | 42) 40 5D 51 (73 | 53) 56 56 40 57 41 41 }
		$a50 = { (74 | 54) 56 47 (63 | 43) 41 5C 50 (72 | 52) 57 57 41 56 40 40 }
		$a51 = { (73 | 53) 51 40 (64 | 44) 46 5B 57 (75 | 55) 50 50 46 51 47 47 }
		$a52 = { (72 | 52) 50 41 (65 | 45) 47 5A 56 (74 | 54) 51 51 47 50 46 46 }
		$a53 = { (71 | 51) 53 42 (66 | 46) 44 59 55 (77 | 57) 52 52 44 53 45 45 }
		$a54 = { (70 | 50) 52 43 (67 | 47) 45 58 54 (76 | 56) 53 53 45 52 44 44 }
		$a55 = { (7F | 5F) 5D 4C (68 | 48) 4A 57 5B (79 | 59) 5C 5C 4A 5D 4B 4B }
		$a56 = { (7E | 5E) 5C 4D (69 | 49) 4B 56 5A (78 | 58) 5D 5D 4B 5C 4A 4A }
		$a57 = { (7D | 5D) 5F 4E (6A | 4A) 48 55 59 (7B | 5B) 5E 5E 48 5F 49 49 }
		$a58 = { (7C | 5C) 5E 4F (6B | 4B) 49 54 58 (7A | 5A) 5F 5F 49 5E 48 48 }
		$a59 = { (7B | 5B) 59 48 (6C | 4C) 4E 53 5F (7D | 5D) 58 58 4E 59 4F 4F }
		$a60 = { (7A | 5A) 58 49 (6D | 4D) 4F 52 5E (7C | 5C) 59 59 4F 58 4E 4E }
		$a61 = { (79 | 59) 5B 4A (6E | 4E) 4C 51 5D (7F | 5F) 5A 5A 4C 5B 4D 4D }
		$a62 = { (78 | 58) 5A 4B (6F | 4F) 4D 50 5C (7E | 5E) 5B 5B 4D 5A 4C 4C }
		$a63 = { (07 | 27) 25 34 (10 | 30) 32 2F 23 (01 | 21) 24 24 32 25 33 33 }
		$a64 = { (06 | 26) 24 35 (11 | 31) 33 2E 22 (00 | 20) 25 25 33 24 32 32 }
		$a65 = { (05 | 25) 27 36 (12 | 32) 30 2D 21 (03 | 23) 26 26 30 27 31 31 }
		$a66 = { (04 | 24) 26 37 (13 | 33) 31 2C 20 (02 | 22) 27 27 31 26 30 30 }
		$a67 = { (03 | 23) 21 30 (14 | 34) 36 2B 27 (05 | 25) 20 20 36 21 37 37 }
		$a68 = { (02 | 22) 20 31 (15 | 35) 37 2A 26 (04 | 24) 21 21 37 20 36 36 }
		$a69 = { (01 | 21) 23 32 (16 | 36) 34 29 25 (07 | 27) 22 22 34 23 35 35 }
		$a70 = { (00 | 20) 22 33 (17 | 37) 35 28 24 (06 | 26) 23 23 35 22 34 34 }
		$a71 = { (0F | 2F) 2D 3C (18 | 38) 3A 27 2B (09 | 29) 2C 2C 3A 2D 3B 3B }
		$a72 = { (0E | 2E) 2C 3D (19 | 39) 3B 26 2A (08 | 28) 2D 2D 3B 2C 3A 3A }
		$a73 = { (0D | 2D) 2F 3E (1A | 3A) 38 25 29 (0B | 2B) 2E 2E 38 2F 39 39 }
		$a74 = { (0C | 2C) 2E 3F (1B | 3B) 39 24 28 (0A | 2A) 2F 2F 39 2E 38 38 }
		$a75 = { (0B | 2B) 29 38 (1C | 3C) 3E 23 2F (0D | 2D) 28 28 3E 29 3F 3F }
		$a76 = { (0A | 2A) 28 39 (1D | 3D) 3F 22 2E (0C | 2C) 29 29 3F 28 3E 3E }
		$a77 = { (09 | 29) 2B 3A (1E | 3E) 3C 21 2D (0F | 2F) 2A 2A 3C 2B 3D 3D }
		$a78 = { (08 | 28) 2A 3B (1F | 3F) 3D 20 2C (0E | 2E) 2B 2B 3D 2A 3C 3C }
		$a79 = { (17 | 37) 35 24 (00 | 20) 22 3F 33 (11 | 31) 34 34 22 35 23 23 }
		$a80 = { (16 | 36) 34 25 (01 | 21) 23 3E 32 (10 | 30) 35 35 23 34 22 22 }
		$a81 = { (15 | 35) 37 26 (02 | 22) 20 3D 31 (13 | 33) 36 36 20 37 21 21 }
		$a82 = { (14 | 34) 36 27 (03 | 23) 21 3C 30 (12 | 32) 37 37 21 36 20 20 }
		$a83 = { (13 | 33) 31 20 (04 | 24) 26 3B 37 (15 | 35) 30 30 26 31 27 27 }
		$a84 = { (12 | 32) 30 21 (05 | 25) 27 3A 36 (14 | 34) 31 31 27 30 26 26 }
		$a85 = { (11 | 31) 33 22 (06 | 26) 24 39 35 (17 | 37) 32 32 24 33 25 25 }
		$a86 = { (10 | 30) 32 23 (07 | 27) 25 38 34 (16 | 36) 33 33 25 32 24 24 }
		$a87 = { (1F | 3F) 3D 2C (08 | 28) 2A 37 3B (19 | 39) 3C 3C 2A 3D 2B 2B }
		$a88 = { (1E | 3E) 3C 2D (09 | 29) 2B 36 3A (18 | 38) 3D 3D 2B 3C 2A 2A }
		$a89 = { (1D | 3D) 3F 2E (0A | 2A) 28 35 39 (1B | 3B) 3E 3E 28 3F 29 29 }
		$a90 = { (1C | 3C) 3E 2F (0B | 2B) 29 34 38 (1A | 3A) 3F 3F 29 3E 28 28 }
		$a91 = { (1B | 3B) 39 28 (0C | 2C) 2E 33 3F (1D | 3D) 38 38 2E 39 2F 2F }
		$a92 = { (1A | 3A) 38 29 (0D | 2D) 2F 32 3E (1C | 3C) 39 39 2F 38 2E 2E }
		$a93 = { (19 | 39) 3B 2A (0E | 2E) 2C 31 3D (1F | 3F) 3A 3A 2C 3B 2D 2D }
		$a94 = { (18 | 38) 3A 2B (0F | 2F) 2D 30 3C (1E | 3E) 3B 3B 2D 3A 2C 2C }
		$a95 = { (27 | 07) 05 14 (30 | 10) 12 0F 03 (21 | 01) 04 04 12 05 13 13 }
		$a96 = { (26 | 06) 04 15 (31 | 11) 13 0E 02 (20 | 00) 05 05 13 04 12 12 }
		$a97 = { (25 | 05) 07 16 (32 | 12) 10 0D 01 (23 | 03) 06 06 10 07 11 11 }
		$a98 = { (24 | 04) 06 17 (33 | 13) 11 0C 00 (22 | 02) 07 07 11 06 10 10 }
		$a99 = { (23 | 03) 01 10 (34 | 14) 16 0B 07 (25 | 05) 00 00 16 01 17 17 }
		$a100 = { (22 | 02) 00 11 (35 | 15) 17 0A 06 (24 | 04) 01 01 17 00 16 16 }
		$a101 = { (21 | 01) 03 12 (36 | 16) 14 09 05 (27 | 07) 02 02 14 03 15 15 }
		$a102 = { (20 | 00) 02 13 (37 | 17) 15 08 04 (26 | 06) 03 03 15 02 14 14 }
		$a103 = { (2F | 0F) 0D 1C (38 | 18) 1A 07 0B (29 | 09) 0C 0C 1A 0D 1B 1B }
		$a104 = { (2E | 0E) 0C 1D (39 | 19) 1B 06 0A (28 | 08) 0D 0D 1B 0C 1A 1A }
		$a105 = { (2D | 0D) 0F 1E (3A | 1A) 18 05 09 (2B | 0B) 0E 0E 18 0F 19 19 }
		$a106 = { (2C | 0C) 0E 1F (3B | 1B) 19 04 08 (2A | 0A) 0F 0F 19 0E 18 18 }
		$a107 = { (2B | 0B) 09 18 (3C | 1C) 1E 03 0F (2D | 0D) 08 08 1E 09 1F 1F }
		$a108 = { (2A | 0A) 08 19 (3D | 1D) 1F 02 0E (2C | 0C) 09 09 1F 08 1E 1E }
		$a109 = { (29 | 09) 0B 1A (3E | 1E) 1C 01 0D (2F | 0F) 0A 0A 1C 0B 1D 1D }
		$a110 = { (28 | 08) 0A 1B (3F | 1F) 1D 00 0C (2E | 0E) 0B 0B 1D 0A 1C 1C }
		$a111 = { (37 | 17) 15 04 (20 | 00) 02 1F 13 (31 | 11) 14 14 02 15 03 03 }
		$a112 = { (36 | 16) 14 05 (21 | 01) 03 1E 12 (30 | 10) 15 15 03 14 02 02 }
		$a113 = { (35 | 15) 17 06 (22 | 02) 00 1D 11 (33 | 13) 16 16 00 17 01 01 }
		$a114 = { (34 | 14) 16 07 (23 | 03) 01 1C 10 (32 | 12) 17 17 01 16 00 00 }
		$a115 = { (33 | 13) 11 00 (24 | 04) 06 1B 17 (35 | 15) 10 10 06 11 07 07 }
		$a116 = { (32 | 12) 10 01 (25 | 05) 07 1A 16 (34 | 14) 11 11 07 10 06 06 }
		$a117 = { (31 | 11) 13 02 (26 | 06) 04 19 15 (37 | 17) 12 12 04 13 05 05 }
		$a118 = { (30 | 10) 12 03 (27 | 07) 05 18 14 (36 | 16) 13 13 05 12 04 04 }
		$a119 = { (3F | 1F) 1D 0C (28 | 08) 0A 17 1B (39 | 19) 1C 1C 0A 1D 0B 0B }
		$a120 = { (3E | 1E) 1C 0D (29 | 09) 0B 16 1A (38 | 18) 1D 1D 0B 1C 0A 0A }
		$a121 = { (3D | 1D) 1F 0E (2A | 0A) 08 15 19 (3B | 1B) 1E 1E 08 1F 09 09 }
		$a122 = { (3C | 1C) 1E 0F (2B | 0B) 09 14 18 (3A | 1A) 1F 1F 09 1E 08 08 }
		$a123 = { (3B | 1B) 19 08 (2C | 0C) 0E 13 1F (3D | 1D) 18 18 0E 19 0F 0F }
		$a124 = { (3A | 1A) 18 09 (2D | 0D) 0F 12 1E (3C | 1C) 19 19 0F 18 0E 0E }
		$a125 = { (39 | 19) 1B 0A (2E | 0E) 0C 11 1D (3F | 1F) 1A 1A 0C 1B 0D 0D }
		$a126 = { (38 | 18) 1A 0B (2F | 0F) 0D 10 1C (3E | 1E) 1B 1B 0D 1A 0C 0C }
		$a127 = { (C7 | E7) E5 F4 (D0 | F0) F2 EF E3 (C1 | E1) E4 E4 F2 E5 F3 F3 }
		$a128 = { (C6 | E6) E4 F5 (D1 | F1) F3 EE E2 (C0 | E0) E5 E5 F3 E4 F2 F2 }
		$a129 = { (C5 | E5) E7 F6 (D2 | F2) F0 ED E1 (C3 | E3) E6 E6 F0 E7 F1 F1 }
		$a130 = { (C4 | E4) E6 F7 (D3 | F3) F1 EC E0 (C2 | E2) E7 E7 F1 E6 F0 F0 }
		$a131 = { (C3 | E3) E1 F0 (D4 | F4) F6 EB E7 (C5 | E5) E0 E0 F6 E1 F7 F7 }
		$a132 = { (C2 | E2) E0 F1 (D5 | F5) F7 EA E6 (C4 | E4) E1 E1 F7 E0 F6 F6 }
		$a133 = { (C1 | E1) E3 F2 (D6 | F6) F4 E9 E5 (C7 | E7) E2 E2 F4 E3 F5 F5 }
		$a134 = { (C0 | E0) E2 F3 (D7 | F7) F5 E8 E4 (C6 | E6) E3 E3 F5 E2 F4 F4 }
		$a135 = { (CF | EF) ED FC (D8 | F8) FA E7 EB (C9 | E9) EC EC FA ED FB FB }
		$a136 = { (CE | EE) EC FD (D9 | F9) FB E6 EA (C8 | E8) ED ED FB EC FA FA }
		$a137 = { (CD | ED) EF FE (DA | FA) F8 E5 E9 (CB | EB) EE EE F8 EF F9 F9 }
		$a138 = { (CC | EC) EE FF (DB | FB) F9 E4 E8 (CA | EA) EF EF F9 EE F8 F8 }
		$a139 = { (CB | EB) E9 F8 (DC | FC) FE E3 EF (CD | ED) E8 E8 FE E9 FF FF }
		$a140 = { (CA | EA) E8 F9 (DD | FD) FF E2 EE (CC | EC) E9 E9 FF E8 FE FE }
		$a141 = { (C9 | E9) EB FA (DE | FE) FC E1 ED (CF | EF) EA EA FC EB FD FD }
		$a142 = { (C8 | E8) EA FB (DF | FF) FD E0 EC (CE | EE) EB EB FD EA FC FC }
		$a143 = { (D7 | F7) F5 E4 (C0 | E0) E2 FF F3 (D1 | F1) F4 F4 E2 F5 E3 E3 }
		$a144 = { (D6 | F6) F4 E5 (C1 | E1) E3 FE F2 (D0 | F0) F5 F5 E3 F4 E2 E2 }
		$a145 = { (D5 | F5) F7 E6 (C2 | E2) E0 FD F1 (D3 | F3) F6 F6 E0 F7 E1 E1 }
		$a146 = { (D4 | F4) F6 E7 (C3 | E3) E1 FC F0 (D2 | F2) F7 F7 E1 F6 E0 E0 }
		$a147 = { (D3 | F3) F1 E0 (C4 | E4) E6 FB F7 (D5 | F5) F0 F0 E6 F1 E7 E7 }
		$a148 = { (D2 | F2) F0 E1 (C5 | E5) E7 FA F6 (D4 | F4) F1 F1 E7 F0 E6 E6 }
		$a149 = { (D1 | F1) F3 E2 (C6 | E6) E4 F9 F5 (D7 | F7) F2 F2 E4 F3 E5 E5 }
		$a150 = { (D0 | F0) F2 E3 (C7 | E7) E5 F8 F4 (D6 | F6) F3 F3 E5 F2 E4 E4 }
		$a151 = { (DF | FF) FD EC (C8 | E8) EA F7 FB (D9 | F9) FC FC EA FD EB EB }
		$a152 = { (DE | FE) FC ED (C9 | E9) EB F6 FA (D8 | F8) FD FD EB FC EA EA }
		$a153 = { (DD | FD) FF EE (CA | EA) E8 F5 F9 (DB | FB) FE FE E8 FF E9 E9 }
		$a154 = { (DC | FC) FE EF (CB | EB) E9 F4 F8 (DA | FA) FF FF E9 FE E8 E8 }
		$a155 = { (DB | FB) F9 E8 (CC | EC) EE F3 FF (DD | FD) F8 F8 EE F9 EF EF }
		$a156 = { (DA | FA) F8 E9 (CD | ED) EF F2 FE (DC | FC) F9 F9 EF F8 EE EE }
		$a157 = { (D9 | F9) FB EA (CE | EE) EC F1 FD (DF | FF) FA FA EC FB ED ED }
		$a158 = { (D8 | F8) FA EB (CF | EF) ED F0 FC (DE | FE) FB FB ED FA EC EC }
		$a159 = { (E7 | C7) C5 D4 (F0 | D0) D2 CF C3 (E1 | C1) C4 C4 D2 C5 D3 D3 }
		$a160 = { (E6 | C6) C4 D5 (F1 | D1) D3 CE C2 (E0 | C0) C5 C5 D3 C4 D2 D2 }
		$a161 = { (E5 | C5) C7 D6 (F2 | D2) D0 CD C1 (E3 | C3) C6 C6 D0 C7 D1 D1 }
		$a162 = { (E4 | C4) C6 D7 (F3 | D3) D1 CC C0 (E2 | C2) C7 C7 D1 C6 D0 D0 }
		$a163 = { (E3 | C3) C1 D0 (F4 | D4) D6 CB C7 (E5 | C5) C0 C0 D6 C1 D7 D7 }
		$a164 = { (E2 | C2) C0 D1 (F5 | D5) D7 CA C6 (E4 | C4) C1 C1 D7 C0 D6 D6 }
		$a165 = { (E1 | C1) C3 D2 (F6 | D6) D4 C9 C5 (E7 | C7) C2 C2 D4 C3 D5 D5 }
		$a166 = { (E0 | C0) C2 D3 (F7 | D7) D5 C8 C4 (E6 | C6) C3 C3 D5 C2 D4 D4 }
		$a167 = { (EF | CF) CD DC (F8 | D8) DA C7 CB (E9 | C9) CC CC DA CD DB DB }
		$a168 = { (EE | CE) CC DD (F9 | D9) DB C6 CA (E8 | C8) CD CD DB CC DA DA }
		$a169 = { (ED | CD) CF DE (FA | DA) D8 C5 C9 (EB | CB) CE CE D8 CF D9 D9 }
		$a170 = { (EC | CC) CE DF (FB | DB) D9 C4 C8 (EA | CA) CF CF D9 CE D8 D8 }
		$a171 = { (EB | CB) C9 D8 (FC | DC) DE C3 CF (ED | CD) C8 C8 DE C9 DF DF }
		$a172 = { (EA | CA) C8 D9 (FD | DD) DF C2 CE (EC | CC) C9 C9 DF C8 DE DE }
		$a173 = { (E9 | C9) CB DA (FE | DE) DC C1 CD (EF | CF) CA CA DC CB DD DD }
		$a174 = { (E8 | C8) CA DB (FF | DF) DD C0 CC (EE | CE) CB CB DD CA DC DC }
		$a175 = { (F7 | D7) D5 C4 (E0 | C0) C2 DF D3 (F1 | D1) D4 D4 C2 D5 C3 C3 }
		$a176 = { (F6 | D6) D4 C5 (E1 | C1) C3 DE D2 (F0 | D0) D5 D5 C3 D4 C2 C2 }
		$a177 = { (F5 | D5) D7 C6 (E2 | C2) C0 DD D1 (F3 | D3) D6 D6 C0 D7 C1 C1 }
		$a178 = { (F4 | D4) D6 C7 (E3 | C3) C1 DC D0 (F2 | D2) D7 D7 C1 D6 C0 C0 }
		$a179 = { (F3 | D3) D1 C0 (E4 | C4) C6 DB D7 (F5 | D5) D0 D0 C6 D1 C7 C7 }
		$a180 = { (F2 | D2) D0 C1 (E5 | C5) C7 DA D6 (F4 | D4) D1 D1 C7 D0 C6 C6 }
		$a181 = { (F1 | D1) D3 C2 (E6 | C6) C4 D9 D5 (F7 | D7) D2 D2 C4 D3 C5 C5 }
		$a182 = { (F0 | D0) D2 C3 (E7 | C7) C5 D8 D4 (F6 | D6) D3 D3 C5 D2 C4 C4 }
		$a183 = { (FF | DF) DD CC (E8 | C8) CA D7 DB (F9 | D9) DC DC CA DD CB CB }
		$a184 = { (FE | DE) DC CD (E9 | C9) CB D6 DA (F8 | D8) DD DD CB DC CA CA }
		$a185 = { (FD | DD) DF CE (EA | CA) C8 D5 D9 (FB | DB) DE DE C8 DF C9 C9 }
		$a186 = { (FC | DC) DE CF (EB | CB) C9 D4 D8 (FA | DA) DF DF C9 DE C8 C8 }
		$a187 = { (FB | DB) D9 C8 (EC | CC) CE D3 DF (FD | DD) D8 D8 CE D9 CF CF }
		$a188 = { (FA | DA) D8 C9 (ED | CD) CF D2 DE (FC | DC) D9 D9 CF D8 CE CE }
		$a189 = { (F9 | D9) DB CA (EE | CE) CC D1 DD (FF | DF) DA DA CC DB CD CD }
		$a190 = { (F8 | D8) DA CB (EF | CF) CD D0 DC (FE | DE) DB DB CD DA CC CC }
		$a191 = { (87 | A7) A5 B4 (90 | B0) B2 AF A3 (81 | A1) A4 A4 B2 A5 B3 B3 }
		$a192 = { (86 | A6) A4 B5 (91 | B1) B3 AE A2 (80 | A0) A5 A5 B3 A4 B2 B2 }
		$a193 = { (85 | A5) A7 B6 (92 | B2) B0 AD A1 (83 | A3) A6 A6 B0 A7 B1 B1 }
		$a194 = { (84 | A4) A6 B7 (93 | B3) B1 AC A0 (82 | A2) A7 A7 B1 A6 B0 B0 }
		$a195 = { (83 | A3) A1 B0 (94 | B4) B6 AB A7 (85 | A5) A0 A0 B6 A1 B7 B7 }
		$a196 = { (82 | A2) A0 B1 (95 | B5) B7 AA A6 (84 | A4) A1 A1 B7 A0 B6 B6 }
		$a197 = { (81 | A1) A3 B2 (96 | B6) B4 A9 A5 (87 | A7) A2 A2 B4 A3 B5 B5 }
		$a198 = { (80 | A0) A2 B3 (97 | B7) B5 A8 A4 (86 | A6) A3 A3 B5 A2 B4 B4 }
		$a199 = { (8F | AF) AD BC (98 | B8) BA A7 AB (89 | A9) AC AC BA AD BB BB }
		$a200 = { (8E | AE) AC BD (99 | B9) BB A6 AA (88 | A8) AD AD BB AC BA BA }
		$a201 = { (8D | AD) AF BE (9A | BA) B8 A5 A9 (8B | AB) AE AE B8 AF B9 B9 }
		$a202 = { (8C | AC) AE BF (9B | BB) B9 A4 A8 (8A | AA) AF AF B9 AE B8 B8 }
		$a203 = { (8B | AB) A9 B8 (9C | BC) BE A3 AF (8D | AD) A8 A8 BE A9 BF BF }
		$a204 = { (8A | AA) A8 B9 (9D | BD) BF A2 AE (8C | AC) A9 A9 BF A8 BE BE }
		$a205 = { (89 | A9) AB BA (9E | BE) BC A1 AD (8F | AF) AA AA BC AB BD BD }
		$a206 = { (88 | A8) AA BB (9F | BF) BD A0 AC (8E | AE) AB AB BD AA BC BC }
		$a207 = { (97 | B7) B5 A4 (80 | A0) A2 BF B3 (91 | B1) B4 B4 A2 B5 A3 A3 }
		$a208 = { (96 | B6) B4 A5 (81 | A1) A3 BE B2 (90 | B0) B5 B5 A3 B4 A2 A2 }
		$a209 = { (95 | B5) B7 A6 (82 | A2) A0 BD B1 (93 | B3) B6 B6 A0 B7 A1 A1 }
		$a210 = { (94 | B4) B6 A7 (83 | A3) A1 BC B0 (92 | B2) B7 B7 A1 B6 A0 A0 }
		$a211 = { (93 | B3) B1 A0 (84 | A4) A6 BB B7 (95 | B5) B0 B0 A6 B1 A7 A7 }
		$a212 = { (92 | B2) B0 A1 (85 | A5) A7 BA B6 (94 | B4) B1 B1 A7 B0 A6 A6 }
		$a213 = { (91 | B1) B3 A2 (86 | A6) A4 B9 B5 (97 | B7) B2 B2 A4 B3 A5 A5 }
		$a214 = { (90 | B0) B2 A3 (87 | A7) A5 B8 B4 (96 | B6) B3 B3 A5 B2 A4 A4 }
		$a215 = { (9F | BF) BD AC (88 | A8) AA B7 BB (99 | B9) BC BC AA BD AB AB }
		$a216 = { (9E | BE) BC AD (89 | A9) AB B6 BA (98 | B8) BD BD AB BC AA AA }
		$a217 = { (9D | BD) BF AE (8A | AA) A8 B5 B9 (9B | BB) BE BE A8 BF A9 A9 }
		$a218 = { (9C | BC) BE AF (8B | AB) A9 B4 B8 (9A | BA) BF BF A9 BE A8 A8 }
		$a219 = { (9B | BB) B9 A8 (8C | AC) AE B3 BF (9D | BD) B8 B8 AE B9 AF AF }
		$a220 = { (9A | BA) B8 A9 (8D | AD) AF B2 BE (9C | BC) B9 B9 AF B8 AE AE }
		$a221 = { (99 | B9) BB AA (8E | AE) AC B1 BD (9F | BF) BA BA AC BB AD AD }
		$a222 = { (98 | B8) BA AB (8F | AF) AD B0 BC (9E | BE) BB BB AD BA AC AC }
		$a223 = { (A7 | 87) 85 94 (B0 | 90) 92 8F 83 (A1 | 81) 84 84 92 85 93 93 }
		$a224 = { (A6 | 86) 84 95 (B1 | 91) 93 8E 82 (A0 | 80) 85 85 93 84 92 92 }
		$a225 = { (A5 | 85) 87 96 (B2 | 92) 90 8D 81 (A3 | 83) 86 86 90 87 91 91 }
		$a226 = { (A4 | 84) 86 97 (B3 | 93) 91 8C 80 (A2 | 82) 87 87 91 86 90 90 }
		$a227 = { (A3 | 83) 81 90 (B4 | 94) 96 8B 87 (A5 | 85) 80 80 96 81 97 97 }
		$a228 = { (A2 | 82) 80 91 (B5 | 95) 97 8A 86 (A4 | 84) 81 81 97 80 96 96 }
		$a229 = { (A1 | 81) 83 92 (B6 | 96) 94 89 85 (A7 | 87) 82 82 94 83 95 95 }
		$a230 = { (A0 | 80) 82 93 (B7 | 97) 95 88 84 (A6 | 86) 83 83 95 82 94 94 }
		$a231 = { (AF | 8F) 8D 9C (B8 | 98) 9A 87 8B (A9 | 89) 8C 8C 9A 8D 9B 9B }
		$a232 = { (AE | 8E) 8C 9D (B9 | 99) 9B 86 8A (A8 | 88) 8D 8D 9B 8C 9A 9A }
		$a233 = { (AD | 8D) 8F 9E (BA | 9A) 98 85 89 (AB | 8B) 8E 8E 98 8F 99 99 }
		$a234 = { (AC | 8C) 8E 9F (BB | 9B) 99 84 88 (AA | 8A) 8F 8F 99 8E 98 98 }
		$a235 = { (AB | 8B) 89 98 (BC | 9C) 9E 83 8F (AD | 8D) 88 88 9E 89 9F 9F }
		$a236 = { (AA | 8A) 88 99 (BD | 9D) 9F 82 8E (AC | 8C) 89 89 9F 88 9E 9E }
		$a237 = { (A9 | 89) 8B 9A (BE | 9E) 9C 81 8D (AF | 8F) 8A 8A 9C 8B 9D 9D }
		$a238 = { (A8 | 88) 8A 9B (BF | 9F) 9D 80 8C (AE | 8E) 8B 8B 9D 8A 9C 9C }
		$a239 = { (B7 | 97) 95 84 (A0 | 80) 82 9F 93 (B1 | 91) 94 94 82 95 83 83 }
		$a240 = { (B6 | 96) 94 85 (A1 | 81) 83 9E 92 (B0 | 90) 95 95 83 94 82 82 }
		$a241 = { (B5 | 95) 97 86 (A2 | 82) 80 9D 91 (B3 | 93) 96 96 80 97 81 81 }
		$a242 = { (B4 | 94) 96 87 (A3 | 83) 81 9C 90 (B2 | 92) 97 97 81 96 80 80 }
		$a243 = { (B3 | 93) 91 80 (A4 | 84) 86 9B 97 (B5 | 95) 90 90 86 91 87 87 }
		$a244 = { (B2 | 92) 90 81 (A5 | 85) 87 9A 96 (B4 | 94) 91 91 87 90 86 86 }
		$a245 = { (B1 | 91) 93 82 (A6 | 86) 84 99 95 (B7 | 97) 92 92 84 93 85 85 }
		$a246 = { (B0 | 90) 92 83 (A7 | 87) 85 98 94 (B6 | 96) 93 93 85 92 84 84 }
		$a247 = { (BF | 9F) 9D 8C (A8 | 88) 8A 97 9B (B9 | 99) 9C 9C 8A 9D 8B 8B }
		$a248 = { (BE | 9E) 9C 8D (A9 | 89) 8B 96 9A (B8 | 98) 9D 9D 8B 9C 8A 8A }
		$a249 = { (BD | 9D) 9F 8E (AA | 8A) 88 95 99 (BB | 9B) 9E 9E 88 9F 89 89 }
		$a250 = { (BC | 9C) 9E 8F (AB | 8B) 89 94 98 (BA | 9A) 9F 9F 89 9E 88 88 }
		$a251 = { (BB | 9B) 99 88 (AC | 8C) 8E 93 9F (BD | 9D) 98 98 8E 99 8F 8F }
		$a252 = { (BA | 9A) 98 89 (AD | 8D) 8F 92 9E (BC | 9C) 99 99 8F 98 8E 8E }
		$a253 = { (B9 | 99) 9B 8A (AE | 8E) 8C 91 9D (BF | 9F) 9A 9A 8C 9B 8D 8D }
		$a254 = { (4D | 6D) 6E 60 65 (4D | 6D) 68 63 73 60 73 78 }  // "LoadLibrary" XOR 0x01
		$a255 = { (4E | 6E) 6D 63 66 (4E | 6E) 6B 60 70 63 70 7B }  // "LoadLibrary" XOR 0x02
		$a256 = { (4F | 6F) 6C 62 67 (4F | 6F) 6A 61 71 62 71 7A }  // etc...
		$a257 = { (48 | 68) 6B 65 60 (48 | 68) 6D 66 76 65 76 7D }
		$a258 = { (49 | 69) 6A 64 61 (49 | 69) 6C 67 77 64 77 7C }
		$a259 = { (4A | 6A) 69 67 62 (4A | 6A) 6F 64 74 67 74 7F }
		$a260 = { (4B | 6B) 68 66 63 (4B | 6B) 6E 65 75 66 75 7E }
		$a261 = { (44 | 64) 67 69 6C (44 | 64) 61 6A 7A 69 7A 71 }
		$a262 = { (45 | 65) 66 68 6D (45 | 65) 60 6B 7B 68 7B 70 }
		$a263 = { (46 | 66) 65 6B 6E (46 | 66) 63 68 78 6B 78 73 }
		$a264 = { (47 | 67) 64 6A 6F (47 | 67) 62 69 79 6A 79 72 }
		$a265 = { (40 | 60) 63 6D 68 (40 | 60) 65 6E 7E 6D 7E 75 }
		$a266 = { (41 | 61) 62 6C 69 (41 | 61) 64 6F 7F 6C 7F 74 }
		$a267 = { (42 | 62) 61 6F 6A (42 | 62) 67 6C 7C 6F 7C 77 }
		$a268 = { (43 | 63) 60 6E 6B (43 | 63) 66 6D 7D 6E 7D 76 }
		$a269 = { (5C | 7C) 7F 71 74 (5C | 7C) 79 72 62 71 62 69 }
		$a270 = { (5D | 7D) 7E 70 75 (5D | 7D) 78 73 63 70 63 68 }
		$a271 = { (5E | 7E) 7D 73 76 (5E | 7E) 7B 70 60 73 60 6B }
		$a272 = { (5F | 7F) 7C 72 77 (5F | 7F) 7A 71 61 72 61 6A }
		$a273 = { (58 | 78) 7B 75 70 (58 | 78) 7D 76 66 75 66 6D }
		$a274 = { (59 | 79) 7A 74 71 (59 | 79) 7C 77 67 74 67 6C }
		$a275 = { (5A | 7A) 79 77 72 (5A | 7A) 7F 74 64 77 64 6F }
		$a276 = { (5B | 7B) 78 76 73 (5B | 7B) 7E 75 65 76 65 6E }
		$a277 = { (54 | 74) 77 79 7C (54 | 74) 71 7A 6A 79 6A 61 }
		$a278 = { (55 | 75) 76 78 7D (55 | 75) 70 7B 6B 78 6B 60 }
		$a279 = { (56 | 76) 75 7B 7E (56 | 76) 73 78 68 7B 68 63 }
		$a280 = { (57 | 77) 74 7A 7F (57 | 77) 72 79 69 7A 69 62 }
		$a281 = { (50 | 70) 73 7D 78 (50 | 70) 75 7E 6E 7D 6E 65 }
		$a282 = { (51 | 71) 72 7C 79 (51 | 71) 74 7F 6F 7C 6F 64 }
		$a283 = { (52 | 72) 71 7F 7A (52 | 72) 77 7C 6C 7F 6C 67 }
		$a284 = { (53 | 73) 70 7E 7B (53 | 73) 76 7D 6D 7E 6D 66 }
		// XOR 0x20 removed because it toggles capitalization and causes [lL]OAD[Ll]IBRARY to match.
		$a286 = { (6D | 4D) 4E 40 45 (6D | 4D) 48 43 53 40 53 58 }
		$a287 = { (6E | 4E) 4D 43 46 (6E | 4E) 4B 40 50 43 50 5B }
		$a288 = { (6F | 4F) 4C 42 47 (6F | 4F) 4A 41 51 42 51 5A }
		$a289 = { (68 | 48) 4B 45 40 (68 | 48) 4D 46 56 45 56 5D }
		$a290 = { (69 | 49) 4A 44 41 (69 | 49) 4C 47 57 44 57 5C }
		$a291 = { (6A | 4A) 49 47 42 (6A | 4A) 4F 44 54 47 54 5F }
		$a292 = { (6B | 4B) 48 46 43 (6B | 4B) 4E 45 55 46 55 5E }
		$a293 = { (64 | 44) 47 49 4C (64 | 44) 41 4A 5A 49 5A 51 }
		$a294 = { (65 | 45) 46 48 4D (65 | 45) 40 4B 5B 48 5B 50 }
		$a295 = { (66 | 46) 45 4B 4E (66 | 46) 43 48 58 4B 58 53 }
		$a296 = { (67 | 47) 44 4A 4F (67 | 47) 42 49 59 4A 59 52 }
		$a297 = { (60 | 40) 43 4D 48 (60 | 40) 45 4E 5E 4D 5E 55 }
		$a298 = { (61 | 41) 42 4C 49 (61 | 41) 44 4F 5F 4C 5F 54 }
		$a299 = { (62 | 42) 41 4F 4A (62 | 42) 47 4C 5C 4F 5C 57 }
		$a300 = { (63 | 43) 40 4E 4B (63 | 43) 46 4D 5D 4E 5D 56 }
		$a301 = { (7C | 5C) 5F 51 54 (7C | 5C) 59 52 42 51 42 49 }
		$a302 = { (7D | 5D) 5E 50 55 (7D | 5D) 58 53 43 50 43 48 }
		$a303 = { (7E | 5E) 5D 53 56 (7E | 5E) 5B 50 40 53 40 4B }
		$a304 = { (7F | 5F) 5C 52 57 (7F | 5F) 5A 51 41 52 41 4A }
		$a305 = { (78 | 58) 5B 55 50 (78 | 58) 5D 56 46 55 46 4D }
		$a306 = { (79 | 59) 5A 54 51 (79 | 59) 5C 57 47 54 47 4C }
		$a307 = { (7A | 5A) 59 57 52 (7A | 5A) 5F 54 44 57 44 4F }
		$a308 = { (7B | 5B) 58 56 53 (7B | 5B) 5E 55 45 56 45 4E }
		$a309 = { (74 | 54) 57 59 5C (74 | 54) 51 5A 4A 59 4A 41 }
		$a310 = { (75 | 55) 56 58 5D (75 | 55) 50 5B 4B 58 4B 40 }
		$a311 = { (76 | 56) 55 5B 5E (76 | 56) 53 58 48 5B 48 43 }
		$a312 = { (77 | 57) 54 5A 5F (77 | 57) 52 59 49 5A 49 42 }
		$a313 = { (70 | 50) 53 5D 58 (70 | 50) 55 5E 4E 5D 4E 45 }
		$a314 = { (71 | 51) 52 5C 59 (71 | 51) 54 5F 4F 5C 4F 44 }
		$a315 = { (72 | 52) 51 5F 5A (72 | 52) 57 5C 4C 5F 4C 47 }
		$a316 = { (73 | 53) 50 5E 5B (73 | 53) 56 5D 4D 5E 4D 46 }
		$a317 = { (0C | 2C) 2F 21 24 (0C | 2C) 29 22 32 21 32 39 }
		$a318 = { (0D | 2D) 2E 20 25 (0D | 2D) 28 23 33 20 33 38 }
		$a319 = { (0E | 2E) 2D 23 26 (0E | 2E) 2B 20 30 23 30 3B }
		$a320 = { (0F | 2F) 2C 22 27 (0F | 2F) 2A 21 31 22 31 3A }
		$a321 = { (08 | 28) 2B 25 20 (08 | 28) 2D 26 36 25 36 3D }
		$a322 = { (09 | 29) 2A 24 21 (09 | 29) 2C 27 37 24 37 3C }
		$a323 = { (0A | 2A) 29 27 22 (0A | 2A) 2F 24 34 27 34 3F }
		$a324 = { (0B | 2B) 28 26 23 (0B | 2B) 2E 25 35 26 35 3E }
		$a325 = { (04 | 24) 27 29 2C (04 | 24) 21 2A 3A 29 3A 31 }
		$a326 = { (05 | 25) 26 28 2D (05 | 25) 20 2B 3B 28 3B 30 }
		$a327 = { (06 | 26) 25 2B 2E (06 | 26) 23 28 38 2B 38 33 }
		$a328 = { (07 | 27) 24 2A 2F (07 | 27) 22 29 39 2A 39 32 }
		$a329 = { (00 | 20) 23 2D 28 (00 | 20) 25 2E 3E 2D 3E 35 }
		$a330 = { (01 | 21) 22 2C 29 (01 | 21) 24 2F 3F 2C 3F 34 }
		$a331 = { (02 | 22) 21 2F 2A (02 | 22) 27 2C 3C 2F 3C 37 }
		$a332 = { (03 | 23) 20 2E 2B (03 | 23) 26 2D 3D 2E 3D 36 }
		$a333 = { (1C | 3C) 3F 31 34 (1C | 3C) 39 32 22 31 22 29 }
		$a334 = { (1D | 3D) 3E 30 35 (1D | 3D) 38 33 23 30 23 28 }
		$a335 = { (1E | 3E) 3D 33 36 (1E | 3E) 3B 30 20 33 20 2B }
		$a336 = { (1F | 3F) 3C 32 37 (1F | 3F) 3A 31 21 32 21 2A }
		$a337 = { (18 | 38) 3B 35 30 (18 | 38) 3D 36 26 35 26 2D }
		$a338 = { (19 | 39) 3A 34 31 (19 | 39) 3C 37 27 34 27 2C }
		$a339 = { (1A | 3A) 39 37 32 (1A | 3A) 3F 34 24 37 24 2F }
		$a340 = { (1B | 3B) 38 36 33 (1B | 3B) 3E 35 25 36 25 2E }
		$a341 = { (14 | 34) 37 39 3C (14 | 34) 31 3A 2A 39 2A 21 }
		$a342 = { (15 | 35) 36 38 3D (15 | 35) 30 3B 2B 38 2B 20 }
		$a343 = { (16 | 36) 35 3B 3E (16 | 36) 33 38 28 3B 28 23 }
		$a344 = { (17 | 37) 34 3A 3F (17 | 37) 32 39 29 3A 29 22 }
		$a345 = { (10 | 30) 33 3D 38 (10 | 30) 35 3E 2E 3D 2E 25 }
		$a346 = { (11 | 31) 32 3C 39 (11 | 31) 34 3F 2F 3C 2F 24 }
		$a347 = { (12 | 32) 31 3F 3A (12 | 32) 37 3C 2C 3F 2C 27 }
		$a348 = { (13 | 33) 30 3E 3B (13 | 33) 36 3D 2D 3E 2D 26 }
		$a349 = { (2C | 0C) 0F 01 04 (2C | 0C) 09 02 12 01 12 19 }
		$a350 = { (2D | 0D) 0E 00 05 (2D | 0D) 08 03 13 00 13 18 }
		$a351 = { (2E | 0E) 0D 03 06 (2E | 0E) 0B 00 10 03 10 1B }
		$a352 = { (2F | 0F) 0C 02 07 (2F | 0F) 0A 01 11 02 11 1A }
		$a353 = { (28 | 08) 0B 05 00 (28 | 08) 0D 06 16 05 16 1D }
		$a354 = { (29 | 09) 0A 04 01 (29 | 09) 0C 07 17 04 17 1C }
		$a355 = { (2A | 0A) 09 07 02 (2A | 0A) 0F 04 14 07 14 1F }
		$a356 = { (2B | 0B) 08 06 03 (2B | 0B) 0E 05 15 06 15 1E }
		$a357 = { (24 | 04) 07 09 0C (24 | 04) 01 0A 1A 09 1A 11 }
		$a358 = { (25 | 05) 06 08 0D (25 | 05) 00 0B 1B 08 1B 10 }
		$a359 = { (26 | 06) 05 0B 0E (26 | 06) 03 08 18 0B 18 13 }
		$a360 = { (27 | 07) 04 0A 0F (27 | 07) 02 09 19 0A 19 12 }
		$a361 = { (20 | 00) 03 0D 08 (20 | 00) 05 0E 1E 0D 1E 15 }
		$a362 = { (21 | 01) 02 0C 09 (21 | 01) 04 0F 1F 0C 1F 14 }
		$a363 = { (22 | 02) 01 0F 0A (22 | 02) 07 0C 1C 0F 1C 17 }
		$a364 = { (23 | 03) 00 0E 0B (23 | 03) 06 0D 1D 0E 1D 16 }
		$a365 = { (3C | 1C) 1F 11 14 (3C | 1C) 19 12 02 11 02 09 }
		$a366 = { (3D | 1D) 1E 10 15 (3D | 1D) 18 13 03 10 03 08 }
		$a367 = { (3E | 1E) 1D 13 16 (3E | 1E) 1B 10 00 13 00 0B }
		$a368 = { (3F | 1F) 1C 12 17 (3F | 1F) 1A 11 01 12 01 0A }
		$a369 = { (38 | 18) 1B 15 10 (38 | 18) 1D 16 06 15 06 0D }
		$a370 = { (39 | 19) 1A 14 11 (39 | 19) 1C 17 07 14 07 0C }
		$a371 = { (3A | 1A) 19 17 12 (3A | 1A) 1F 14 04 17 04 0F }
		$a372 = { (3B | 1B) 18 16 13 (3B | 1B) 1E 15 05 16 05 0E }
		$a373 = { (34 | 14) 17 19 1C (34 | 14) 11 1A 0A 19 0A 01 }
		$a374 = { (35 | 15) 16 18 1D (35 | 15) 10 1B 0B 18 0B 00 }
		$a375 = { (36 | 16) 15 1B 1E (36 | 16) 13 18 08 1B 08 03 }
		$a376 = { (37 | 17) 14 1A 1F (37 | 17) 12 19 09 1A 09 02 }
		$a377 = { (30 | 10) 13 1D 18 (30 | 10) 15 1E 0E 1D 0E 05 }
		$a378 = { (31 | 11) 12 1C 19 (31 | 11) 14 1F 0F 1C 0F 04 }
		$a379 = { (32 | 12) 11 1F 1A (32 | 12) 17 1C 0C 1F 0C 07 }
		$a380 = { (33 | 13) 10 1E 1B (33 | 13) 16 1D 0D 1E 0D 06 }
		$a381 = { (CC | EC) EF E1 E4 (CC | EC) E9 E2 F2 E1 F2 F9 }
		$a382 = { (CD | ED) EE E0 E5 (CD | ED) E8 E3 F3 E0 F3 F8 }
		$a383 = { (CE | EE) ED E3 E6 (CE | EE) EB E0 F0 E3 F0 FB }
		$a384 = { (CF | EF) EC E2 E7 (CF | EF) EA E1 F1 E2 F1 FA }
		$a385 = { (C8 | E8) EB E5 E0 (C8 | E8) ED E6 F6 E5 F6 FD }
		$a386 = { (C9 | E9) EA E4 E1 (C9 | E9) EC E7 F7 E4 F7 FC }
		$a387 = { (CA | EA) E9 E7 E2 (CA | EA) EF E4 F4 E7 F4 FF }
		$a388 = { (CB | EB) E8 E6 E3 (CB | EB) EE E5 F5 E6 F5 FE }
		$a389 = { (C4 | E4) E7 E9 EC (C4 | E4) E1 EA FA E9 FA F1 }
		$a390 = { (C5 | E5) E6 E8 ED (C5 | E5) E0 EB FB E8 FB F0 }
		$a391 = { (C6 | E6) E5 EB EE (C6 | E6) E3 E8 F8 EB F8 F3 }
		$a392 = { (C7 | E7) E4 EA EF (C7 | E7) E2 E9 F9 EA F9 F2 }
		$a393 = { (C0 | E0) E3 ED E8 (C0 | E0) E5 EE FE ED FE F5 }
		$a394 = { (C1 | E1) E2 EC E9 (C1 | E1) E4 EF FF EC FF F4 }
		$a395 = { (C2 | E2) E1 EF EA (C2 | E2) E7 EC FC EF FC F7 }
		$a396 = { (C3 | E3) E0 EE EB (C3 | E3) E6 ED FD EE FD F6 }
		$a397 = { (DC | FC) FF F1 F4 (DC | FC) F9 F2 E2 F1 E2 E9 }
		$a398 = { (DD | FD) FE F0 F5 (DD | FD) F8 F3 E3 F0 E3 E8 }
		$a399 = { (DE | FE) FD F3 F6 (DE | FE) FB F0 E0 F3 E0 EB }
		$a400 = { (DF | FF) FC F2 F7 (DF | FF) FA F1 E1 F2 E1 EA }
		$a401 = { (D8 | F8) FB F5 F0 (D8 | F8) FD F6 E6 F5 E6 ED }
		$a402 = { (D9 | F9) FA F4 F1 (D9 | F9) FC F7 E7 F4 E7 EC }
		$a403 = { (DA | FA) F9 F7 F2 (DA | FA) FF F4 E4 F7 E4 EF }
		$a404 = { (DB | FB) F8 F6 F3 (DB | FB) FE F5 E5 F6 E5 EE }
		$a405 = { (D4 | F4) F7 F9 FC (D4 | F4) F1 FA EA F9 EA E1 }
		$a406 = { (D5 | F5) F6 F8 FD (D5 | F5) F0 FB EB F8 EB E0 }
		$a407 = { (D6 | F6) F5 FB FE (D6 | F6) F3 F8 E8 FB E8 E3 }
		$a408 = { (D7 | F7) F4 FA FF (D7 | F7) F2 F9 E9 FA E9 E2 }
		$a409 = { (D0 | F0) F3 FD F8 (D0 | F0) F5 FE EE FD EE E5 }
		$a410 = { (D1 | F1) F2 FC F9 (D1 | F1) F4 FF EF FC EF E4 }
		$a411 = { (D2 | F2) F1 FF FA (D2 | F2) F7 FC EC FF EC E7 }
		$a412 = { (D3 | F3) F0 FE FB (D3 | F3) F6 FD ED FE ED E6 }
		$a413 = { (EC | CC) CF C1 C4 (EC | CC) C9 C2 D2 C1 D2 D9 }
		$a414 = { (ED | CD) CE C0 C5 (ED | CD) C8 C3 D3 C0 D3 D8 }
		$a415 = { (EE | CE) CD C3 C6 (EE | CE) CB C0 D0 C3 D0 DB }
		$a416 = { (EF | CF) CC C2 C7 (EF | CF) CA C1 D1 C2 D1 DA }
		$a417 = { (E8 | C8) CB C5 C0 (E8 | C8) CD C6 D6 C5 D6 DD }
		$a418 = { (E9 | C9) CA C4 C1 (E9 | C9) CC C7 D7 C4 D7 DC }
		$a419 = { (EA | CA) C9 C7 C2 (EA | CA) CF C4 D4 C7 D4 DF }
		$a420 = { (EB | CB) C8 C6 C3 (EB | CB) CE C5 D5 C6 D5 DE }
		$a421 = { (E4 | C4) C7 C9 CC (E4 | C4) C1 CA DA C9 DA D1 }
		$a422 = { (E5 | C5) C6 C8 CD (E5 | C5) C0 CB DB C8 DB D0 }
		$a423 = { (E6 | C6) C5 CB CE (E6 | C6) C3 C8 D8 CB D8 D3 }
		$a424 = { (E7 | C7) C4 CA CF (E7 | C7) C2 C9 D9 CA D9 D2 }
		$a425 = { (E0 | C0) C3 CD C8 (E0 | C0) C5 CE DE CD DE D5 }
		$a426 = { (E1 | C1) C2 CC C9 (E1 | C1) C4 CF DF CC DF D4 }
		$a427 = { (E2 | C2) C1 CF CA (E2 | C2) C7 CC DC CF DC D7 }
		$a428 = { (E3 | C3) C0 CE CB (E3 | C3) C6 CD DD CE DD D6 }
		$a429 = { (FC | DC) DF D1 D4 (FC | DC) D9 D2 C2 D1 C2 C9 }
		$a430 = { (FD | DD) DE D0 D5 (FD | DD) D8 D3 C3 D0 C3 C8 }
		$a431 = { (FE | DE) DD D3 D6 (FE | DE) DB D0 C0 D3 C0 CB }
		$a432 = { (FF | DF) DC D2 D7 (FF | DF) DA D1 C1 D2 C1 CA }
		$a433 = { (F8 | D8) DB D5 D0 (F8 | D8) DD D6 C6 D5 C6 CD }
		$a434 = { (F9 | D9) DA D4 D1 (F9 | D9) DC D7 C7 D4 C7 CC }
		$a435 = { (FA | DA) D9 D7 D2 (FA | DA) DF D4 C4 D7 C4 CF }
		$a436 = { (FB | DB) D8 D6 D3 (FB | DB) DE D5 C5 D6 C5 CE }
		$a437 = { (F4 | D4) D7 D9 DC (F4 | D4) D1 DA CA D9 CA C1 }
		$a438 = { (F5 | D5) D6 D8 DD (F5 | D5) D0 DB CB D8 CB C0 }
		$a439 = { (F6 | D6) D5 DB DE (F6 | D6) D3 D8 C8 DB C8 C3 }
		$a440 = { (F7 | D7) D4 DA DF (F7 | D7) D2 D9 C9 DA C9 C2 }
		$a441 = { (F0 | D0) D3 DD D8 (F0 | D0) D5 DE CE DD CE C5 }
		$a442 = { (F1 | D1) D2 DC D9 (F1 | D1) D4 DF CF DC CF C4 }
		$a443 = { (F2 | D2) D1 DF DA (F2 | D2) D7 DC CC DF CC C7 }
		$a444 = { (F3 | D3) D0 DE DB (F3 | D3) D6 DD CD DE CD C6 }
		$a445 = { (8C | AC) AF A1 A4 (8C | AC) A9 A2 B2 A1 B2 B9 }
		$a446 = { (8D | AD) AE A0 A5 (8D | AD) A8 A3 B3 A0 B3 B8 }
		$a447 = { (8E | AE) AD A3 A6 (8E | AE) AB A0 B0 A3 B0 BB }
		$a448 = { (8F | AF) AC A2 A7 (8F | AF) AA A1 B1 A2 B1 BA }
		$a449 = { (88 | A8) AB A5 A0 (88 | A8) AD A6 B6 A5 B6 BD }
		$a450 = { (89 | A9) AA A4 A1 (89 | A9) AC A7 B7 A4 B7 BC }
		$a451 = { (8A | AA) A9 A7 A2 (8A | AA) AF A4 B4 A7 B4 BF }
		$a452 = { (8B | AB) A8 A6 A3 (8B | AB) AE A5 B5 A6 B5 BE }
		$a453 = { (84 | A4) A7 A9 AC (84 | A4) A1 AA BA A9 BA B1 }
		$a454 = { (85 | A5) A6 A8 AD (85 | A5) A0 AB BB A8 BB B0 }
		$a455 = { (86 | A6) A5 AB AE (86 | A6) A3 A8 B8 AB B8 B3 }
		$a456 = { (87 | A7) A4 AA AF (87 | A7) A2 A9 B9 AA B9 B2 }
		$a457 = { (80 | A0) A3 AD A8 (80 | A0) A5 AE BE AD BE B5 }
		$a458 = { (81 | A1) A2 AC A9 (81 | A1) A4 AF BF AC BF B4 }
		$a459 = { (82 | A2) A1 AF AA (82 | A2) A7 AC BC AF BC B7 }
		$a460 = { (83 | A3) A0 AE AB (83 | A3) A6 AD BD AE BD B6 }
		$a461 = { (9C | BC) BF B1 B4 (9C | BC) B9 B2 A2 B1 A2 A9 }
		$a462 = { (9D | BD) BE B0 B5 (9D | BD) B8 B3 A3 B0 A3 A8 }
		$a463 = { (9E | BE) BD B3 B6 (9E | BE) BB B0 A0 B3 A0 AB }
		$a464 = { (9F | BF) BC B2 B7 (9F | BF) BA B1 A1 B2 A1 AA }
		$a465 = { (98 | B8) BB B5 B0 (98 | B8) BD B6 A6 B5 A6 AD }
		$a466 = { (99 | B9) BA B4 B1 (99 | B9) BC B7 A7 B4 A7 AC }
		$a467 = { (9A | BA) B9 B7 B2 (9A | BA) BF B4 A4 B7 A4 AF }
		$a468 = { (9B | BB) B8 B6 B3 (9B | BB) BE B5 A5 B6 A5 AE }
		$a469 = { (94 | B4) B7 B9 BC (94 | B4) B1 BA AA B9 AA A1 }
		$a470 = { (95 | B5) B6 B8 BD (95 | B5) B0 BB AB B8 AB A0 }
		$a471 = { (96 | B6) B5 BB BE (96 | B6) B3 B8 A8 BB A8 A3 }
		$a472 = { (97 | B7) B4 BA BF (97 | B7) B2 B9 A9 BA A9 A2 }
		$a473 = { (90 | B0) B3 BD B8 (90 | B0) B5 BE AE BD AE A5 }
		$a474 = { (91 | B1) B2 BC B9 (91 | B1) B4 BF AF BC AF A4 }
		$a475 = { (92 | B2) B1 BF BA (92 | B2) B7 BC AC BF AC A7 }
		$a476 = { (93 | B3) B0 BE BB (93 | B3) B6 BD AD BE AD A6 }
		$a477 = { (AC | 8C) 8F 81 84 (AC | 8C) 89 82 92 81 92 99 }
		$a478 = { (AD | 8D) 8E 80 85 (AD | 8D) 88 83 93 80 93 98 }
		$a479 = { (AE | 8E) 8D 83 86 (AE | 8E) 8B 80 90 83 90 9B }
		$a480 = { (AF | 8F) 8C 82 87 (AF | 8F) 8A 81 91 82 91 9A }
		$a481 = { (A8 | 88) 8B 85 80 (A8 | 88) 8D 86 96 85 96 9D }
		$a482 = { (A9 | 89) 8A 84 81 (A9 | 89) 8C 87 97 84 97 9C }
		$a483 = { (AA | 8A) 89 87 82 (AA | 8A) 8F 84 94 87 94 9F }
		$a484 = { (AB | 8B) 88 86 83 (AB | 8B) 8E 85 95 86 95 9E }
		$a485 = { (A4 | 84) 87 89 8C (A4 | 84) 81 8A 9A 89 9A 91 }
		$a486 = { (A5 | 85) 86 88 8D (A5 | 85) 80 8B 9B 88 9B 90 }
		$a487 = { (A6 | 86) 85 8B 8E (A6 | 86) 83 88 98 8B 98 93 }
		$a488 = { (A7 | 87) 84 8A 8F (A7 | 87) 82 89 99 8A 99 92 }
		$a489 = { (A0 | 80) 83 8D 88 (A0 | 80) 85 8E 9E 8D 9E 95 }
		$a490 = { (A1 | 81) 82 8C 89 (A1 | 81) 84 8F 9F 8C 9F 94 }
		$a491 = { (A2 | 82) 81 8F 8A (A2 | 82) 87 8C 9C 8F 9C 97 }
		$a492 = { (A3 | 83) 80 8E 8B (A3 | 83) 86 8D 9D 8E 9D 96 }
		$a493 = { (BC | 9C) 9F 91 94 (BC | 9C) 99 92 82 91 82 89 }
		$a494 = { (BD | 9D) 9E 90 95 (BD | 9D) 98 93 83 90 83 88 }
		$a495 = { (BE | 9E) 9D 93 96 (BE | 9E) 9B 90 80 93 80 8B }
		$a496 = { (BF | 9F) 9C 92 97 (BF | 9F) 9A 91 81 92 81 8A }
		$a497 = { (B8 | 98) 9B 95 90 (B8 | 98) 9D 96 86 95 86 8D }
		$a498 = { (B9 | 99) 9A 94 91 (B9 | 99) 9C 97 87 94 87 8C }
		$a499 = { (BA | 9A) 99 97 92 (BA | 9A) 9F 94 84 97 84 8F }
		$a500 = { (BB | 9B) 98 96 93 (BB | 9B) 9E 95 85 96 85 8E }
		$a501 = { (B4 | 94) 97 99 9C (B4 | 94) 91 9A 8A 99 8A 81 }
		$a502 = { (B5 | 95) 96 98 9D (B5 | 95) 90 9B 8B 98 8B 80 }
		$a503 = { (B6 | 96) 95 9B 9E (B6 | 96) 93 98 88 9B 88 83 }
		$a504 = { (B7 | 97) 94 9A 9F (B7 | 97) 92 99 89 9A 89 82 }
		$a505 = { (B0 | 90) 93 9D 98 (B0 | 90) 95 9E 8E 9D 8E 85 }
		$a506 = { (B1 | 91) 92 9C 99 (B1 | 91) 94 9F 8F 9C 8F 84 }
		$a507 = { (B2 | 92) 91 9F 9A (B2 | 92) 97 9C 8C 9F 8C 87 }
	condition:
		any of them
}


rule BITS_CLSID_MITRE___T1197 {
	    meta:
        description = "References the BITS service."
        author = "Ivan Kwiatkowski (@JusticeRage)"
        // The BITS service seems to be used heavily by EquationGroup.
    strings:
        $uuid_background_copy_manager_1_5 =     { 1F 77 87 F0 4F D7 1A 4C BB 8A E1 6A CA 91 24 EA }
        $uuid_background_copy_manager_2_0 =     { 12 AD 18 6D E3 BD 93 43 B3 11 09 9C 34 6E 6D F9 }
        $uuid_background_copy_manager_2_5 =     { D6 98 CA 03 5D FF B8 49 AB C6 03 DD 84 12 70 20 }
        $uuid_background_copy_manager_3_0 =     { A7 DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_manager_4_0 =     { 6B F5 6D BB CE CA DC 11 99 92 00 19 B9 3A 3A 84 }
        $uuid_background_copy_manager_5_0 =     { 4C A3 CC 1E 8A E8 E3 44 8D 6A 89 21 BD E9 E4 52 }
        $uuid_background_copy_manager =         { 4B D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97 }
        $uuid_ibackground_copy_manager =        { 0D 4C E3 5C C9 0D 1F 4C 89 7C DA A1 B7 8C EE 7C }
        $uuid_background_copy_qmanager =        { 69 AD 4A EE 51 BE 43 9B A9 2C 86 AE 49 0E 8B 30 }
        $uuid_ibits_peer_cache_administration = { AD DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
        $uuid_background_copy_callback =        { C7 99 EA 97 86 01 D4 4A 8D F9 C5 B4 E0 ED 6B 22 }
    condition:
        any of them
}

rule inject_thread_MITRE___T1055 {
    meta:
        author = "x0r"
        description = "Code injection with CreateRemoteThread in a remote process"
	version = "0.1"
    strings:
        $c1 = "OpenProcess"
        $c2 = "VirtualAllocEx"
        $c3 = "NtWriteVirtualMemory"
        $c4 = "WriteProcessMemory"
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c7 )
}

rule screeshot_write_MITRE___T1113
{
    meta:
        description = "Takes Screenshot"
    strings:
        $ie = "SCREENSHOT"
        $ff = "WRITE_FILE"
    condition:
        all of them
}

rule process_enum_MITRE___T1057
{
    meta:
        description = "Enumerates Process"
    strings:
        $ie = "PROCESS_ENUM"
        $ie1 = "PROCESS_ENUM_1"
    condition:
        any of them
}

rule input_capture_MITRE___T1056
{
    meta:
        descrition = "Input Capture API calls"

    strings:
        $a1 = "KEYBOARD_INFO"
        $a2 = "KEYBOARD_INPUT_1"
        $a3 = "KEYBOARD_INPUT_2"
        $a4 = "KEYBOARD_INPUT_3"
        $a5 = "KEYBOARD_INPUT_4"
        $a6 = "KEYBOARD_INPUT_5"
        $a7 = "KEYBOARD_INPUT_6"
        $a8 = "KEYBOARD_INPUT_7"
        $a9 = "MOUSE"
        $a10 = "MOUSE_1"

    condition:
        any of them
}

rule audio_capture:_MITRE___
{
    meta:
        description = "Audio Capture API Calls"

    strings:
        $a1 = "AUDIO_IN"
        $a2 = "AUDIO_IN"

    condition:
        any of them
}


rule system_info_MITRE___T1082_T1033
{
    meta:
        description = "Getting host information"

    strings:
        $a1 = "SYSTEM_INFO"
        $a2 = "SYSTEM_INFO_1"
        $a3 = "SYSTEM_INFO_2"
        $a4 = "SYSTEM_INFO_LOCALE"

    condition:
        any of them
}



rule os_info_MITRE___T1135_T1033_T1057_T1012
{
    meta:
        description = "Getting os info"

    strings:
        $a1 = "OS_INFO_1"
        $a2 = "OS_INFO_2"
        $a3 = "OS_INFO_3"

    condition:
        any of them
}

rule host_info_MITRE___T1082_T1033
 {
    meta:
        description = "Getting host information"

    strings:
        $a1 = "HOST_INFO_1"
        $a2 = "HOST_INFO_2"
        $a3 = "HOST_INFO_3"
        $a4 = "HOST_INFO_4"

    condition:
        any of them
}

rule disk_info_MITRE___T1082_T1033
 {
    meta:
        description= "Getting host information"

    strings:
        $a1 = "DISK_INFO_1"
        $a2 = "DISK_INFO_2"
        $a3 = "DISK_INFO_3"
        $a4 = "DISK_INFO_4"
        $a5 = "DISK_INFO_5"
        $a6 = "DISK_INFO_6"

    condition:
        any of them
 }

rule window_discovery_MITRE___T1010
 {
    meta:
        description= "Getting host information"

    strings:
	    $a1 = "DESKTOP_ENUM"

	condition:
	    any of them
}

rule user_impersonation:_MITRE___
{
    meta:
        description= "Run Process as"

    strings:
        $a1 = "PROCESS_CREATE_USER"
        $a2 = "PROCESS_CREATE_LOGON"

    condition:
        any of them
}

rule send_recv_MITRE___T1065_T1041
{
    meta:
        description= "Communication using send and recv"

    strings:
        $a1 = "WSASEND"
        $a2 = "LISTEN"
        $a3 = "RECV"
        $a4 = "WSARECV"
        $a5 = "SEND"
        $a6 = "WASSEND"
        $a7 = "SEND_TO"
        $a8 = "WSASEND_TO"
        $a9 = "RECV_FROM"
        $a10 = "WSARECV_FROM"

    condition:
        any of them
}

rule downloader_MITRE___T1071_T1105
{
    meta:
        description = "Downloads a file"
    strings:
        $a1 = "DOWNLOAD_FILE_CACHE"
        $a2 = "DOWNLOAD_FILE"

    condition:
        any of them
}

rule ftp_get_put_MITRE___T1071_T1105
{
    meta:
        description = "Downloads a file"
    strings:
        $a1 = "FTP_GET"
        $a2 = "FTP_PUT"

    condition:
        any of them
}


rule file_enum_MITRE___T1083
{
    meta:
        description = "File and drive enumeration"
    strings:
        $a1 = "DRIVES_ITER_1"
        $a2 = "DRIVES_ITER_2"
        $a3 = "FILE_ITER"

    condition:
        any of them
}

rule process_injection_MITRE___T1055
{
    meta:
        description = "Remode code injection"
    strings:
        $a1 = "REMOTE_THREAD_INJECTION"
        $a2 = "REMOTE_THREAD_1"
        $a3 = "REMOTE_THREAD_INJECTION_1"

    condition:
        any of them

}

rule downloade_from_url_MITRE___T1071_T1105
{
    meta:
        description = "Remode code injection"
    strings:
        $a1 = "DOWNLOADER"
        $a2 = "DOWNLOADER_1"
        $a3 = "DOWNLOADER_2"
        $a4 = "DOWNLOADER_3"
    condition:
        any of them
}

rule query_reg_MITRE___T1012
{
    meta:
        description = "Remode code injection"
    strings:
        $a1 = "REG_QUERY"

    condition:
        any of them
}

rule sc_screate_MITRE___T1035_T1050
{
    meta:
        description = "Start Service"

    strings:
        $a1 = "CREATE_SERVICE"
        $a2 = "START_SERVICE"

    condition:
        any of them
}

rule win_hook_MITRE___T1179
{
    meta:
        description = "SetWindowsHook"

    strings:
        $a1 = "WINHOOK"

    condition:
        any of them
}

rule time_zone_MITRE___T1124
{
    meta:
        description = "Get time zone"

    strings:
        $a1 = "TIME_ZONE"

    condition:
        any of them
}

rule logoonuser_MITRE___T1033_T1087
{
    meta:
        description = "LogonUser"

    strings:
        $a1 = "USER"

    condition:
        any of them
}

rule impersonate_user_MITRE___T1134
{
    meta:
        description = "LogonUser"

    strings:
        $a1 = "USER_IMPERSONATE"

    condition:
        any of them
}
