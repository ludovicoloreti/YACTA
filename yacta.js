console.log(`
██╗   ██╗ █████╗  ██████╗████████╗ █████╗
╚██╗ ██╔╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗
 ╚████╔╝ ███████║██║        ██║   ███████║
  ╚██╔╝  ██╔══██║██║        ██║   ██╔══██║
   ██║   ██║  ██║╚██████╗   ██║   ██║  ██║
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝
\tYet Another Cyber Threat Analyzer
\t\t\tMade by N4pst3r
`);

const fs = require("fs");
const yara = require("yara");
const path = require("path");
const axios = require("axios");
const { exec } = require("child_process");
const vtReportUrl = "https://www.virustotal.com/vtapi/v2/file/report";
const vtAPIKey = process.env.VIRUSTOTAL_API_KEY;
const sha256File = require("sha256-file");
const md5File = require("md5-file");
const FileType = require("file-type");

const yaraDirectoryFiles = __dirname + "/yara/";
const jsonDirectoryFiles = __dirname + "/json/";
const filesDirectoryFiles = __dirname + "/files/";

if (!process.argv.slice(2)[0]) {
  console.log(
    '\n\nUSAGE:\n\tPut your Sample in the "./file" directory, then:\n\n\t\t node yacta.js [ FILE_NAME_TO_ANALYZE ]\n\n'
  );
  process.kill(process.pid);
}
const urlFile = filesDirectoryFiles + process.argv.slice(2)[0];
const fileName = path.basename(urlFile);
//  "malware" file
const malware = fs.readFileSync(urlFile);
// yara rules
const rules = [{ filename: yaraDirectoryFiles + "index.yar" }];
//  where file will be saved
const analysisFinalFile =
  "./results/analysis_" + fileName.toLowerCase().replace(".", "_") + ".json";
const elkFinalFIle =
  "./results/elastic_" + fileName.toLowerCase().replace(".", "_") + ".json";

// JSON files
const apt_techniques_json = JSON.parse(
  fs.readFileSync(jsonDirectoryFiles + "apt_techniques.json", "utf-8")
);
const mitre_json = JSON.parse(
  fs.readFileSync(jsonDirectoryFiles + "mitre.json", "utf-8")
);
const mitigations_json_list = JSON.parse(
  fs.readFileSync(jsonDirectoryFiles + "mitigations.json", "utf-8")
);
// HASH
const sha256 = sha256File(urlFile);
const md5hash = md5File.sync(urlFile);
// URL and IP Matcher
const URLregex = new RegExp(
  "^(http[s]?:\\/\\/(www\\.)?|ftp:\\/\\/(www\\.)?|www\\.){1}([0-9A-Za-z-\\.@:%_+~#=]+)+((\\.[a-zA-Z]{2,3})+)(/(.)*)?(\\?(.)*)?"
);
const IPregex = new RegExp(
  "^(?:[01]?dd?|2[0-4]d|25[0-5])(?:[01]?dd?|2[0-4]d|25[0-5])(?:[01]?dd?|2[0-4]d|25[0-5])(?:[01]?dd?|2[0-4]d|25[0-5])$"
);
const fnBuffer = new Buffer(analysisFinalFile).toString("base64");
let mitre_techniques = "";
const aptGroups = Object.keys(apt_techniques_json);
const aptTechniques = {};
const now = new Date();
// final json structure
let simpleAnalysis = {
  file: { name: fileName, path: urlFile, type: {} },
  hash: { sha256: sha256, md5: md5hash },
  virustotal: {
    total: 0,
    detected: 0,
    undetected: 0
  },
  yara_matched: 0,
  mitre_techniques: [],
  mitre_phases_matched: [],
  URI_matched: []
};
let malwareAnalysis = {
  file: { name: fileName, path: urlFile, type: {}, fn: fnBuffer },
  hash: { sha256: sha256, md5: md5hash },
  yara: {
    signatures: [],
    n_matched: 0
  },
  mitre_matrix: [
    {
      phase: "Initial Access",
      techniques: []
    },
    {
      phase: "Execution",
      techniques: []
    },
    {
      phase: "Persistence",
      techniques: []
    },
    {
      phase: "Privilege Escalation",
      techniques: []
    },
    {
      phase: "Defense Evasion",
      techniques: []
    },
    {
      phase: "Credential Access",
      techniques: []
    },
    {
      phase: "Discovery",
      techniques: []
    },
    {
      phase: "Lateral Movement",
      techniques: []
    },
    {
      phase: "Collection",
      techniques: []
    },
    {
      phase: "Command and Control",
      techniques: []
    },
    {
      phase: "Exfiltration",
      techniques: []
    },
    {
      phase: "Impact",
      techniques: []
    }
  ],
  virustotal: {
    AV: [],
    total: 0,
    detected: 0,
    undetected: 0
  },
  URLs: [],
  mitre_techniques: [],
  mitigations: [],
  attribution: [],
  timestamp: {
    default: now.toISOString(),
    locale: now.toLocaleString(),
    timestamp: +now
  }
};

(async () => {
  const fType = await FileType.fromFile(urlFile);
  malwareAnalysis.file.type = fType;
  simpleAnalysis.file.type = fType;
})();

yara.initialize(function(error) {
  if (error) {
    console.error(error.message);
  } else {
    const scanner = yara.createScanner();
    scanner.configure({ rules: rules }, function(error, warnings) {
      if (error) {
        if (error instanceof yara.CompileRulesError) {
          console.error(error.message + ": " + JSON.stringify(error.errors));
        } else {
          console.error(error.message);
        }
      } else {
        const req = { buffer: malware };
        scanner.scan(req, function(error, result) {
          if (error) {
            console.error(error.message);
          } else {
            const mitreString = "_MITRE___";
            malwareAnalysis.yara.n_matched = result.rules.length;
            simpleAnalysis.yara_matched = malwareAnalysis.yara.n_matched;
            result.rules.map(el => {
              if (el.id.toUpperCase().includes(mitreString.toUpperCase())) {
                const mitreYara = el.id.split(mitreString);
                const techniques = mitreYara[1].split("_");
                techniques.map(t => {
                  mitre_techniques += t + ", ".trim();
                });
                malwareAnalysis.yara.signatures.push({
                  name: mitreYara[0],
                  techniques: techniques,
                  description: el.metas.filter(
                    val => val.id === "description"
                  )[0].value
                });
              } else {
                malwareAnalysis.yara.signatures.push({
                  name: el.id,
                  techniques: null,
                  description:
                    el.metas.filter(val => val.id === "description").length > 0
                      ? el.metas.filter(val => val.id === "description")[0]
                          .value
                      : null
                });
              }
            });
            if (mitre_techniques && mitre_techniques.length > 0)
              malwareAnalysis.mitre_techniques = [
                ...new Set(mitre_techniques.replace(/,\s*$/, "").split(","))
              ];

            simpleAnalysis.mitre_techniques = malwareAnalysis.mitre_techniques;
            axios
              .get(vtReportUrl, {
                params: {
                  apikey: vtAPIKey,
                  resource: sha256
                }
              })
              .then(function(response) {
                if (response.status === 200) {
                  if (response.data.response_code !== 0) {
                    const avResults = response.data.scans;
                    malwareAnalysis.virustotal.total = Object.keys(
                      avResults
                    ).length;
                    Object.keys(avResults).map(el => {
                      avResults[el].detected
                        ? malwareAnalysis.virustotal.detected++
                        : malwareAnalysis.virustotal.undetected++;
                      malwareAnalysis.virustotal.AV.push({
                        name: el,
                        detected: avResults[el].detected,
                        result: avResults[el].result
                      });
                    });
                    simpleAnalysis.virustotal.detected =
                      malwareAnalysis.virustotal.detected;
                    simpleAnalysis.virustotal.undetected =
                      malwareAnalysis.virustotal.undetected;
                    simpleAnalysis.virustotal.total =
                      malwareAnalysis.virustotal.total;
                  }
                } else {
                  console.log("Virustotal Error. Retry in a few minutes.");
                }
                malwareAnalysis.mitre_techniques.map(el => {
                  aptGroups.map(group => {
                    apt_techniques_json[group].map(techniques => {
                      if (el === techniques) {
                        if (aptTechniques[group]) {
                          aptTechniques[group].push(techniques);
                        } else {
                          aptTechniques[group] = [techniques];
                        }
                      }
                    });
                  });
                });
                let counter = {};
                let percentage = {};
                Object.keys(aptTechniques).map(el => {
                  aptGroups.map(group => {
                    if (el === group) {
                      percentage[el] =
                        (aptTechniques[el].length * 100) /
                        apt_techniques_json[group].length;
                      counter[el] = aptTechniques[el].length;
                    }
                  });
                });
                Object.keys(counter).map(el => {
                  malwareAnalysis.attribution.push({
                    group: el,
                    techniques_matched: counter[el],
                    percentage: percentage[el],
                    techniques: aptTechniques[el]
                  });
                });

                const jsonMitre = Object.keys(mitre_json);
                let phaseNames = [];
                malwareAnalysis.mitre_techniques.map(element => {
                  jsonMitre.map(phase => {
                    Object.keys(mitre_json[phase]).map(technique => {
                      if (element === technique) {
                        malwareAnalysis.mitre_matrix.map(val => {
                          if (val.phase === phase) {
                            phaseNames.push(phase);
                            val.techniques.push({
                              id: element,
                              name: Object.values(
                                mitre_json[phase][technique]
                              )[0],
                              description: Object.values(
                                mitre_json[phase][technique]
                              )[1],
                              url: Object.values(
                                mitre_json[phase][technique]
                              )[2]
                            });
                          }
                        });
                      }
                    });
                  });
                });
                simpleAnalysis.mitre_phases_matched = [...new Set(phaseNames)];
                malwareAnalysis.mitre_techniques.map(element => {
                  mitigations_json_list.forEach(el => {
                    if (element === el.techniques) {
                      if (el.mitigations.length > 0) {
                        malwareAnalysis.mitigations.push({
                          technique: element,
                          list: el.mitigations
                        });
                      }
                    }
                  });
                });

                exec("strings " + urlFile, (error, stdout, stderr) => {
                  if (error) {
                    console.log(`error: ${error.message}`);
                  } else if (stderr) {
                    console.log(`stderr: ${stderr}`);
                  } else {
                    stdout.split("\n").map(el => {
                      if (URLregex.test(el))
                        malwareAnalysis.URLs.push(
                          el.trim().replace(/\d+$/, "")
                        );
                      if (IPregex.test(el))
                        malwareAnalysis.URLs.push(el.trim());
                    });
                    simpleAnalysis.URI_matched = malwareAnalysis.URLs;
                  }
                  fs.writeFileSync(
                    analysisFinalFile,
                    JSON.stringify(malwareAnalysis, null, 2),
                    "utf-8"
                  );
                  fs.writeFileSync(
                    elkFinalFIle,
                    JSON.stringify(simpleAnalysis, null, 2),
                    "utf-8"
                  );
                });
              })
              .catch(function(error) {
                console.log(error);
              });
          }
        });
      }
    });
  }
});

console.log("File: " + fileName);
console.log("SHA256: " + sha256);
console.log("Date: " + now.toDateString() + ", " + now.toTimeString());
