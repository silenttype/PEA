# POWERSHELL EXTRACTOR ANALYZER v1.0 (PEA)
Authors: 

    Christopher Del Fierro (silenttype)    
    John Angelo Lipata (fakeJAVL)
    
![pea](https://user-images.githubusercontent.com/32733587/52629010-ce9f7c80-2ef3-11e9-99ee-a92077df4447.png)
 
PEA is a python script used to decode and extract PowerShell codes in clear text – executed in an isolated environment generating a report outlining the behavior of the executed PowerShell commands.

The concept of this tool is very simple. PEA will execute the malware sample inside a Windows 10 sandbox environment where PowerShell v5 (at least) is installed. And, with the help of PowerShell’s advanced logging features: Script-Block Logging and Module Logging – PEA will extract and make sense what the malware is attempting to do with PowerShell.

This tool aims to cut-down the analysis time of malware leveraging PowerShell – helping to defeat obfuscation and embedding techniques used by cybercriminals.

Simple Diagram:

Malware Sample -> PEA.PY = Analysis.csv and Scriptblock.txt


This proof-of-concept tool was presented in AVAR 2018 Goa, India titled *Cracking the Shell: Cutting the Analysis Time of PowerShell Attacks Using Sandbox and Advanced Logging.*

## 1. INSTALLATION and USAGE

### 1.1 Installation:
Simply download the whole repository and have PEA executed in a shell.

Python Pea.py [sample]

    Example:

    $ Python3 Pea.py '/home/gab/_virus/MalwareUsingPS/emotet.doc

PEA will attempt to identify and supply the correct file format of the submitted file.

Outputs:


    •	Console Output
    •	scriptblock.txt – script blocks representation of invoked PowerShell codes
    •	analysis.csv – CSV output of dissected PowerShell commands, urls, IOCs, shellcodes, descriptions, script artifacts and many more

### 1.2 Supported MimeTypes:
    •	application/msword (.DOC)  
    •	application/vnd.openxmlformats-officedocument.wordprocessingml.document (.DOCX)
    •	application/x-dosexec(.EXE)  
    •	application/pdf (.PDF)  
    •	text/html(.HTML)  
    •	application/javascript(.JS)  
    •	application/vnd.ms-powerpoint(.PPT)  
    •	application/vnd.openxmlformats-officedocument.presentationml.presentation(.PPTX)  
    •	application/vnd.ms-excel(.XLS)  
    •	application/vnd.openxmlformats-officedocument.spreadsheetml.sheet(.XLSX)  
  
  Technically, even if the mimetype of the submitted sample is not listed above, as long as the submitted file is renamed with proper extension (e.g. sample.ps1), PEA will process this sample accordingly. Just make sure that the default application that will be invoked by the sample inside the VM is installed (e.g. submitted sample.DOC needs Microsoft Word installed inside the sandbox).
![outputpea](https://user-images.githubusercontent.com/32733587/52629192-1d4d1680-2ef4-11e9-963e-3d67f6a974f0.png)


## 2. REQUIREMENTS
Requirements will be split into two: Host and Guest. Since this is a PoC to begin with, hard requirement is VMware Workstation non-negotiable. You can edit PEA to port it using any other virtualization software like VirtualBox, etc. 😊 

### 2.1 Host
    •	Supported Host OS: Linux or Windows
    •	VMWare Workstation
    •	Python3 with
        o	numpy
        o	python-magic
        o	colorama

### 2.2 Guest
    •	Guest OS: any Windows 10 flavor
    •	PowerShell v5 (minimum) installed
    •	Microsoft Office
        o	Word
        o	Excel
        o	PowerPoint
    •	PDF Reader
    •	Internet Explorer
    •	Any other software that might invoke PowerShell
*Note: All security settings (OS and installed applications) should be set to lowest possible in order for the malware to execute properly without restrictions.*

## 3. CONFIGURATIONS
### 3.1 Preparing Windows 10 VM
1.	Create a directory where PEA will be copied and executed (e.g C:\PEA)
2.	Create a directory where the sample to be submitted will execute (e.g. C:\_virus)
3.	Make sure PowerShell is installed and running with no problems
4.	Take a snapshot of the VM while running
5.	Name your snapshot (e.g. PEA)
### 3.2 Configuring PEA
1.	Locate PEA.INI and adjust the settings as you see fit
![peaini](https://user-images.githubusercontent.com/32733587/52629220-2e962300-2ef4-11e9-838a-a4f5bda2e029.png)

## 4. BUGS and LIMITATIONS
PEA is not perfect and may have some/many bugs. Contact us for bugs, but there will be no promises for any updates as of the moment.

Some identified limitations are:

    •	Malware that disables Enhanced Logging
    •	Malware that downgrades PowerShell version 
    •	Malware that floods the logging events


## 5. REFERENCES
    •	Greater Visibility Through PowerShell Logging (hxxps://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
    •	PowerShell ♥ the Blue Team (hxxps://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)
    •	Cracking the Shell (hxxps://aavar.org/avar2018/index.php/cracking-the-shell/)
