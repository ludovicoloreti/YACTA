# YACTA
Yet Another Cyber Threat Analyzer, is a simple Malware Analyzer.

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

And after that, you wiill see in the "results" folder two files: one, the simpliest, to use (if you want) with the stack ELK, and the other, more verbose, as you want.

Thank you, cya!

P.S. tested on MacOS
