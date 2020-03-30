# YACTA

Yet Another Cyber Threat Analyzer, is a simple Malware Analyzer wrote in NodeJS.

![Yet Another Cyber Threat Analyzer](https://raw.githubusercontent.com/ludovicoloreti/YACTA/master/logo.png)

Static and some dynamic analysis are done using yara, virustotal, strings to get ip/urls, and a self made statistics using the Mitre ATT&CK matrix, so it shows up for each tactics, the techinques used by the Sample submitted, and eventually mitigations.

## INSTALL

First, be sure to install YARA global:

```
# CentOS/Red Hat
sudo yum install yara-devel

# Debian/Ubuntu
sudo apt-get install libyara-dev

# MacOS (using homebrew)
sudo brew install yara
```

Then after git cloned the repo, go to the root and type

```
npm install
```

## USAGE

To use it, make sure to have a "/file" folder inside the root project as shown here, with the list (or the lonely) of Sample to analyze, then simply type

```
node yacta.js [ FILE_NAME_TO_ANALYZE ]
```

And after that, you will see in the "results" folder two files: one, the simpliest, to use (if you want) with the stack ELK, and the other, more verbose, as you want.

## EXAMPLE RESULT

```json
{
  "file": {
    "name": "malware.zztop",
    "path": "/Users/somebody/somewhere/YACTA/files/malware.zztop",
    "type": {
      "ext": "exe",
      "mime": "application/x-msdownload"
    },
    "fn": "Li9yZXN1bHRzL2FuYWx5c2lzX21hbHdhcmVfenp0b3AuanNvbg"
  },
  "hash": {
    "sha256": "2ec3847d7b70047309ddf6030dad2480dd738bdc2597271720ccb28699f86ef5",
    "md5": "e9bf284ba44f49d5629c3109bfc8f50f"
  },
  "yara": {
    "signatures": [
      {
        "name": "CRC32_poly_Constant",
        "techniques": ["T1032", "T1022"],
        "description": "Look for CRC32 [poly]"
      },
      {
        "name": "Delphi_Copy",
        "techniques": ["T1032", "T1022"],
        "description": "Look for Copy function"
      },
      {
        "name": "logoonuser",
        "techniques": ["T1033", "T1087"],
        "description": "LogonUser"
      },
      {
        "name": "disable_dep",
        "techniques": null,
        "description": "Bypass DEP"
      },
      {
        "name": "create_process",
        "techniques": null,
        "description": "Create a new process"
      },
      {
        "name": "escalate_priv",
        "techniques": null,
        "description": "Escalade priviledges"
      },
      {
        "name": "win_registry",
        "techniques": null,
        "description": "Affect system registries"
      },
      {
        "name": "win_token",
        "techniques": null,
        "description": "May affect system token"
      },
      {
        "name": "win_files_operation",
        "techniques": null,
        "description": "May affect private profile"
      },
      {
        "name": "IP",
        "techniques": null,
        "description": "Contains IPs"
      },
      {
        "name": "url",
        "techniques": null,
        "description": "Contains URLs"
      },
      {
        "name": "IsPE32",
        "techniques": null,
        "description": null
      },
      {
        "name": "IsWindowsGUI",
        "techniques": null,
        "description": null
      },
      {
        "name": "IsPacked",
        "techniques": null,
        "description": "Entropy Check"
      },
      {
        "name": "HasOverlay",
        "techniques": null,
        "description": "Overlay Check"
      },
      {
        "name": "HasDigitalSignature",
        "techniques": null,
        "description": "DigitalSignature Check"
      },
      {
        "name": "borland_delphi",
        "techniques": null,
        "description": "Borland Delphi 2.0 - 7.0 / 2005 - 2007"
      }
    ],
    "n_matched": 17
  },
  "mitre_matrix": [
    {
      "phase": "Initial Access",
      "techniques": []
    },
    {
      "phase": "Execution",
      "techniques": []
    },
    {
      "phase": "Persistence",
      "techniques": []
    },
    {
      "phase": "Privilege Escalation",
      "techniques": []
    },
    {
      "phase": "Defense Evasion",
      "techniques": []
    },
    {
      "phase": "Credential Access",
      "techniques": []
    },
    {
      "phase": "Discovery",
      "techniques": [
        {
          "id": "T1033",
          "name": "System Owner/User Discovery",
          "description": "Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs.",
          "url": "https://attack.mitre.org/techniques/T1033/"
        },
        {
          "id": "T1087",
          "name": "Account Discovery",
          "description": "Adversaries may attempt to get a listing of local system or domain accounts.",
          "url": "https://attack.mitre.org/techniques/T1087/"
        }
      ]
    },
    {
      "phase": "Lateral Movement",
      "techniques": []
    },
    {
      "phase": "Collection",
      "techniques": []
    },
    {
      "phase": "Command and Control",
      "techniques": [
        {
          "id": "T1032",
          "name": "Standard Cryptographic Protocol",
          "description": "Adversaries may explicitly employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if necessary secret keys are encoded and/or generated within malware samples/configuration files.",
          "url": "https://attack.mitre.org/techniques/T1032/"
        }
      ]
    },
    {
      "phase": "Exfiltration",
      "techniques": [
        {
          "id": "T1022",
          "name": "Data Encrypted",
          "description": "Data is encrypted before being exfiltrated in order to hide the information that is being exfiltrated from detection or to make the exfiltration less conspicuous upon inspection by a defender. The encryption is performed by a utility, programming library, or custom algorithm on the data itself and is considered separate from any encryption performed by the command and control or file transfer protocol. Common file archive formats that can encrypt files are RAR and zip.",
          "url": "https://attack.mitre.org/techniques/T1022/"
        }
      ]
    },
    {
      "phase": "Impact",
      "techniques": []
    }
  ],
  "virustotal": {
    "AV": [
      {
        "name": "Bkav",
        "detected": true,
        "result": "W32.HfsAdware.216A"
      },
      {
        "name": "MicroWorld-eScan",
        "detected": true,
        "result": "Gen:Variant.Application.KMSPico.1"
      },
      {
        "name": "VBA32",
        "detected": false,
        "result": null
      },
      {
        "name": "CMC",
        "detected": false,
        "result": null
      },
      {
        "name": "CAT-QuickHeal",
        "detected": true,
        "result": "Risktool.Procpatcher"
      },
      {
        "name": "ALYac",
        "detected": false,
        "result": null
      },
      {
        "name": "Cylance",
        "detected": true,
        "result": "Unsafe"
      },
      {
        "name": "Zillya",
        "detected": false,
        "result": null
      },
      {
        "name": "SUPERAntiSpyware",
        "detected": false,
        "result": null
      },
      {
        "name": "Sangfor",
        "detected": true,
        "result": "Malware"
      },
      {
        "name": "K7AntiVirus",
        "detected": true,
        "result": "Hacktool ( 004b4f751 )"
      },
      {
        "name": "Alibaba",
        "detected": true,
        "result": "HackTool:Win32/AutoKMS.6ac2d66c"
      },
      {
        "name": "K7GW",
        "detected": true,
        "result": "Hacktool ( 004b4f751 )"
      },
      {
        "name": "Cybereason",
        "detected": true,
        "result": "malicious.ba44f4"
      },
      {
        "name": "Arcabit",
        "detected": true,
        "result": "Application.Hacktool.KMSActivator.CD"
      },
      {
        "name": "TrendMicro",
        "detected": true,
        "result": "HKTL_AUTOKMS"
      },
      {
        "name": "BitDefenderTheta",
        "detected": true,
        "result": "Gen:NN.ZemsilF.34100.dr1@aeVkj6m"
      },
      {
        "name": "F-Prot",
        "detected": true,
        "result": "W32/AutoKMS.A"
      },
      {
        "name": "TotalDefense",
        "detected": false,
        "result": null
      },
      {
        "name": "Baidu",
        "detected": false,
        "result": null
      },
      {
        "name": "TrendMicro-HouseCall",
        "detected": true,
        "result": "HKTL_AUTOKMS"
      },
      {
        "name": "Avast",
        "detected": true,
        "result": "Other:PUP-gen [PUP]"
      },
      {
        "name": "ClamAV",
        "detected": true,
        "result": "Win.Trojan.Agent-6288138-0"
      },
      {
        "name": "Kaspersky",
        "detected": true,
        "result": "not-a-virus:RiskTool.Win64.ProcPatcher.a"
      },
      {
        "name": "BitDefender",
        "detected": true,
        "result": "Gen:Variant.Application.KMSPico.1"
      },
      {
        "name": "NANO-Antivirus",
        "detected": false,
        "result": null
      },
      {
        "name": "Paloalto",
        "detected": false,
        "result": null
      },
      {
        "name": "AegisLab",
        "detected": true,
        "result": "Riskware.Win64.ProcPatcher.1!c"
      },
      {
        "name": "Rising",
        "detected": true,
        "result": "Trojan.Win32.Generic.168BB9F2 (C64:YzY0Og/ZuvtWKers)"
      },
      {
        "name": "Endgame",
        "detected": true,
        "result": "malicious (high confidence)"
      },
      {
        "name": "Emsisoft",
        "detected": true,
        "result": "Application.HackTool (A)"
      },
      {
        "name": "Comodo",
        "detected": true,
        "result": "Malware@#2b330x5fxevm6"
      },
      {
        "name": "F-Secure",
        "detected": false,
        "result": null
      },
      {
        "name": "DrWeb",
        "detected": true,
        "result": "Trojan.Moneyinst.709"
      },
      {
        "name": "VIPRE",
        "detected": true,
        "result": "Trojan.Win32.Generic!BT"
      },
      {
        "name": "Invincea",
        "detected": true,
        "result": "heuristic"
      },
      {
        "name": "McAfee-GW-Edition",
        "detected": true,
        "result": "Crack-KMS"
      },
      {
        "name": "SentinelOne",
        "detected": false,
        "result": null
      },
      {
        "name": "Trapmine",
        "detected": false,
        "result": null
      },
      {
        "name": "FireEye",
        "detected": true,
        "result": "Gen:Variant.Application.KMSPico.1"
      },
      {
        "name": "Sophos",
        "detected": true,
        "result": "KMS Activator (PUA)"
      },
      {
        "name": "APEX",
        "detected": false,
        "result": null
      },
      {
        "name": "Cyren",
        "detected": true,
        "result": "W32/AutoKMS.IGSM-9049"
      },
      {
        "name": "Jiangmin",
        "detected": true,
        "result": "HackTool.MSIL.dgy"
      },
      {
        "name": "Webroot",
        "detected": true,
        "result": "W32.Hacktool.Kms"
      },
      {
        "name": "Avira",
        "detected": false,
        "result": null
      },
      {
        "name": "Fortinet",
        "detected": true,
        "result": "Riskware/IdleKMS"
      },
      {
        "name": "Antiy-AVL",
        "detected": false,
        "result": null
      },
      {
        "name": "Kingsoft",
        "detected": false,
        "result": null
      },
      {
        "name": "Microsoft",
        "detected": true,
        "result": "HackTool:Win32/AutoKMS"
      },
      {
        "name": "ViRobot",
        "detected": true,
        "result": "Adware.Autokms.2921448"
      },
      {
        "name": "ZoneAlarm",
        "detected": true,
        "result": "not-a-virus:RiskTool.Win64.ProcPatcher.a"
      },
      {
        "name": "Avast-Mobile",
        "detected": false,
        "result": null
      },
      {
        "name": "TACHYON",
        "detected": false,
        "result": null
      },
      {
        "name": "AhnLab-V3",
        "detected": true,
        "result": "HackTool/Win32.Crack.C509549"
      },
      {
        "name": "Acronis",
        "detected": true,
        "result": "suspicious"
      },
      {
        "name": "McAfee",
        "detected": true,
        "result": "Crack-KMS"
      },
      {
        "name": "MAX",
        "detected": true,
        "result": "malware (ai score=100)"
      },
      {
        "name": "Ad-Aware",
        "detected": false,
        "result": null
      },
      {
        "name": "Malwarebytes",
        "detected": false,
        "result": null
      },
      {
        "name": "Zoner",
        "detected": false,
        "result": null
      },
      {
        "name": "ESET-NOD32",
        "detected": true,
        "result": "a variant of MSIL/HackTool.IdleKMS.C potentially unsafe"
      },
      {
        "name": "Tencent",
        "detected": false,
        "result": null
      },
      {
        "name": "Yandex",
        "detected": true,
        "result": "Riskware.ProcPatcher!"
      },
      {
        "name": "Ikarus",
        "detected": true,
        "result": "HackTool.Win32.AutoKMS"
      },
      {
        "name": "eGambit",
        "detected": false,
        "result": null
      },
      {
        "name": "GData",
        "detected": true,
        "result": "BAT.Application.Agent.TPLV1J"
      },
      {
        "name": "MaxSecure",
        "detected": false,
        "result": null
      },
      {
        "name": "AVG",
        "detected": true,
        "result": "Other:PUP-gen [PUP]"
      },
      {
        "name": "Panda",
        "detected": false,
        "result": null
      },
      {
        "name": "CrowdStrike",
        "detected": false,
        "result": null
      },
      {
        "name": "Qihoo-360",
        "detected": false,
        "result": null
      }
    ],
    "total": 72,
    "detected": 45,
    "undetected": 27
  },
  "URLs": ["http://ocsp.thawte.com", "http://ts-ocsp.ws.symantec.com"],
  "mitre_techniques": ["T1032", "T1022", "T1033", "T1087"],
  "mitigations": [
    {
      "technique": "T1032",
      "list": [
        {
          "id": "M1031",
          "name": "Network Intrusion Prevention",
          "url": "https://attack.mitre.org/mitigations/M1031/"
        },
        {
          "id": "M1020",
          "name": "SSL/TLS Inspection",
          "url": "https://attack.mitre.org/mitigations/M1020/"
        }
      ]
    },
    {
      "technique": "T1087",
      "list": [
        {
          "id": "M1028",
          "name": "Operating System Configuration",
          "url": "https://attack.mitre.org/mitigations/M1028/"
        }
      ]
    }
  ],
  "attribution": [
    {
      "group": "APT33",
      "techniques_matched": 1,
      "percentage": 4.761904761904762,
      "techniques": ["T1032"]
    },
    {
      "group": "BRONZE BUTLER",
      "techniques_matched": 3,
      "percentage": 9.67741935483871,
      "techniques": ["T1032", "T1022", "T1087"]
    },
    {
      "group": "Cobalt Group",
      "techniques_matched": 1,
      "percentage": 3.4482758620689653,
      "techniques": ["T1032"]
    },
    {
      "group": "FIN6",
      "techniques_matched": 3,
      "percentage": 12.5,
      "techniques": ["T1032", "T1022", "T1087"]
    },
    {
      "group": "FIN8",
      "techniques_matched": 1,
      "percentage": 4,
      "techniques": ["T1032"]
    },
    {
      "group": "Lazarus Group",
      "techniques_matched": 3,
      "percentage": 5.454545454545454,
      "techniques": ["T1032", "T1022", "T1033"]
    },
    {
      "group": "Machete",
      "techniques_matched": 1,
      "percentage": 8.333333333333334,
      "techniques": ["T1032"]
    },
    {
      "group": "OilRig",
      "techniques_matched": 3,
      "percentage": 6.818181818181818,
      "techniques": ["T1032", "T1033", "T1087"]
    },
    {
      "group": "Stealth Falcon",
      "techniques_matched": 2,
      "percentage": 14.285714285714286,
      "techniques": ["T1032", "T1033"]
    },
    {
      "group": "Taidoor",
      "techniques_matched": 1,
      "percentage": 100,
      "techniques": ["T1032"]
    },
    {
      "group": "Tropic Trooper",
      "techniques_matched": 2,
      "percentage": 11.11111111111111,
      "techniques": ["T1032", "T1033"]
    },
    {
      "group": "APT32",
      "techniques_matched": 3,
      "percentage": 5.454545454545454,
      "techniques": ["T1022", "T1033", "T1087"]
    },
    {
      "group": "CopyKittens",
      "techniques_matched": 1,
      "percentage": 16.666666666666668,
      "techniques": ["T1022"]
    },
    {
      "group": "Honeybee",
      "techniques_matched": 1,
      "percentage": 4.545454545454546,
      "techniques": ["T1022"]
    },
    {
      "group": "Ke3chang",
      "techniques_matched": 2,
      "percentage": 7.407407407407407,
      "techniques": ["T1022", "T1087"]
    },
    {
      "group": "Kimsuky",
      "techniques_matched": 1,
      "percentage": 5.2631578947368425,
      "techniques": ["T1022"]
    },
    {
      "group": "Patchwork",
      "techniques_matched": 2,
      "percentage": 5.882352941176471,
      "techniques": ["T1022", "T1033"]
    },
    {
      "group": "Soft Cell",
      "techniques_matched": 2,
      "percentage": 7.142857142857143,
      "techniques": ["T1022", "T1033"]
    },
    {
      "group": "Threat Group-3390",
      "techniques_matched": 2,
      "percentage": 4.761904761904762,
      "techniques": ["T1022", "T1087"]
    },
    {
      "group": "Turla",
      "techniques_matched": 1,
      "percentage": 2.6315789473684212,
      "techniques": ["T1022"]
    },
    {
      "group": "menuPass",
      "techniques_matched": 2,
      "percentage": 6.25,
      "techniques": ["T1022", "T1087"]
    },
    {
      "group": "APT19",
      "techniques_matched": 1,
      "percentage": 5,
      "techniques": ["T1033"]
    },
    {
      "group": "APT3",
      "techniques_matched": 2,
      "percentage": 4.545454545454546,
      "techniques": ["T1033", "T1087"]
    },
    {
      "group": "APT37",
      "techniques_matched": 1,
      "percentage": 3.7037037037037037,
      "techniques": ["T1033"]
    },
    {
      "group": "APT39",
      "techniques_matched": 1,
      "percentage": 5.555555555555555,
      "techniques": ["T1033"]
    },
    {
      "group": "APT41",
      "techniques_matched": 1,
      "percentage": 2.4390243902439024,
      "techniques": ["T1033"]
    },
    {
      "group": "Dragonfly 2.0",
      "techniques_matched": 2,
      "percentage": 4.878048780487805,
      "techniques": ["T1033", "T1087"]
    },
    {
      "group": "FIN10",
      "techniques_matched": 1,
      "percentage": 11.11111111111111,
      "techniques": ["T1033"]
    },
    {
      "group": "Gamaredon Group",
      "techniques_matched": 1,
      "percentage": 12.5,
      "techniques": ["T1033"]
    },
    {
      "group": "Magic Hound",
      "techniques_matched": 1,
      "percentage": 3.7037037037037037,
      "techniques": ["T1033"]
    },
    {
      "group": "MuddyWater",
      "techniques_matched": 1,
      "percentage": 3.225806451612903,
      "techniques": ["T1033"]
    },
    {
      "group": "APT1",
      "techniques_matched": 1,
      "percentage": 6.25,
      "techniques": ["T1087"]
    },
    {
      "group": "Poseidon Group",
      "techniques_matched": 1,
      "percentage": 14.285714285714286,
      "techniques": ["T1087"]
    },
    {
      "group": "admin@338",
      "techniques_matched": 1,
      "percentage": 8.333333333333334,
      "techniques": ["T1087"]
    }
  ],
  "timestamp": {
    "default": "2020-03-27T21:05:15.930Z",
    "locale": "2020-3-27 22:05:15",
    "timestamp": 1585343115930
  }
}
```

### BYE

Thank you, cya!

P.S. tested on MacOS

### ART SKETCH

MMMMMMMMMMMMMMMMMMMMmsyNMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMM/..hMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMy:MMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMN.mMMMMMMMmymMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMM+sMMMMMMM:.+MMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMh-MMMMMMN-dMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMddmMMMMMMMM-dMMMMM/sMMMMMMMMMd/--+NMMM
MMMMMMMMMMd-.../NMMMMMM++dddms:MMMMMMMMMM:....sMMM
MMMMMMMMMMs.....dMMms/........:sNMMMMmy++ys/+yMMMM
MMMMMMMMMMMho+sy/o+..............oho/odMMMMMMMMMMM
MMMMMMMMMMMMMMMMm-.................dMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMM:................../MMMMMMMMMMMMMM
MdsshMMMMMMMMMMm....................NMMMMMMMMMMMMM
/....:hyyssoooo+....................yhdmNMMMMMMmdM
:....-hmmNNMMMMMo..................odhyysooooo/..-
NyoosNMMMMMMMMMMM+................-mMMMMMMMMMMmooh
MMMMMMMMMMMMMMMmo/s/............/ddo/sdMNdhmMMMMMM
MMMMMMMMMMNMNs/omMMMh.o/:----ohNMMMMMms-....:mMMMM
MMMMMMMMN-.-+hMMMMMN:yMMMMMy:MMMMMMMMMM......sMMMM
MMMMMMMMMsoyMMMMMMM++MMMMMMN.mMMMMMMMMMd/--:sMMMMM
MMMMMMMMMMMMMMMMMMh:NMMMMMMM:odMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMm-dMMMMMMM:...oMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMM:yMMMMMMMMo-.-yMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMh-.NMMMMMMMMMMNMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMNsyMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
