"""Helper functions for PEA"""
import csv
import re
import json
import configparser
import os
import datetime as dt
import numpy as np
from collections import OrderedDict

WORKING_DIR = os.path.dirname(os.path.realpath(__file__))

class bcolors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    GREY = '\033[90m'
    BLACK = '\033[90m'
    DEFAULT = '\033[99m'
    BLACKBG = '\033[40m'
    YELLOWBG = '\033[43m'
    REDBG = '\033[41m'
    PURPLEBG = '\033[45m'



def ReadDictJson(Dict_Json):
    """Dictionary.json reader"""
    try:
        with open (Dict_Json, "r") as stream:
            data = json.load(stream)
        return data
    except IOError as e:
        # print (e)
        print (bcolors.RED + "\n[IOError] Unable to open:" + bcolors.ENDC, Dict_Json)
        return(True)


def ReadJson(JSONFILE):
    """Dictionary.json reader"""
    try:
        with open (JSONFILE, "r") as stream:
            data = json.loads(stream.read(),strict=False)
            if type(data) is dict:
                # convert dict to list here
                ConvertToList(JSONFILE)
                data = ReadJson(JSONFILE)
                data = list(data)
        return data
    except IOError as e:
        # print (e)
        print (bcolors.RED +"\n[IOError] Unable to open:" + bcolors.ENDC, JSONFILE)
        return(True)


def ConvertToList(JSONFILE):
    with open(JSONFILE, 'r') as old_buffer, open("./eventlogs/temp.txt", 'w') as new_buffer:
        # copy until nth byte
        new_buffer.write(old_buffer.read(0))
        # insert new content
        new_buffer.write('[')
        # copy the rest of the file
        new_buffer.write(old_buffer.read())
        new_buffer.seek(0, 2)
        new_buffer.write(']')
        # rename temp.txt to 4104.txt
        os.remove(JSONFILE)
        os.rename("./eventlogs/temp.txt", JSONFILE)


def ReadFile(fileToRead):
    """Generic file reader/opener"""
    try:
        with open(fileToRead, "r") as stream:
            data = stream.readlines()
        return data
    except IOError as e:
        #print (e)
        print (bcolors.RED + "\n[IOError] Unable to open:" + bcolors.ENDC, fileToRead)
        return True


def Read4103(FilePath4103):
    """Reads 4103.txt and generates keywords to compare to dictionary.yaml"""
    # Group keywords in the following format:
    # PROCESS
    # NEW-OBJECT
    # COMMAND
    # ADD-TYPE
    # PARAMS
    # Returns sorted result in list form
    keywords = []
    r4103 = ReadFile(FilePath4103)

    #Check if 4103.txt exists
    if (r4103 == True): return (True)

    for line in r4103:
        if 'ParameterBinding(Start-Process)'.casefold() in line.casefold():
            if 'ParameterBinding(Start-Process): name="FilePath"; value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "PROCESS:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(New-Object)'.casefold() in line.casefold():
            if 'value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "NEW-OBJECT:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(Get-WmiObject)'.casefold() in line.casefold():
            if 'value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "NEW-OBJECT:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(Add-Type)'.casefold() in line.casefold():
            if 'ParameterBinding(Add-Type): name="Namespace"; value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "ADD-TYPE:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
            elif 'ParameterBinding(Add-Type): name="AssemblyName"; value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "ADD-TYPE:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(Add-Type)'.casefold() in line.casefold():
            if 'ParameterBinding(Remove-Item): name="Path"; value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "REMOVE:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(Get-Command)'.casefold() in line.casefold():
            if 'value="' in line:
                varValue = line.split('value=', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "COMMAND:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(Test-Path): name="Path"; value="'.casefold() in line.casefold():
            varValue = line.split('value=', 1)[1].strip('"')
            varValue = varValue.strip('"\n')
            if varValue != '':
                toAdd = "TEST-PATH:: " + varValue
                if toAdd not in keywords:
                    keywords.append(toAdd)
        elif '        Command Name = '.casefold() in line.casefold():
                varValue = line.split('        Command Name = ', 1)[1].strip('"')
                varValue = varValue.strip('"\n')
                if varValue != '':
                    toAdd = "COMMAND:: " + varValue
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif re.match(r'.*host application = .*powershell', line, re.I):
            if 'sample.PS1'.casefold() in line.casefold(): continue
            varValuelist = line.split('Host Application = ', 1)[1].strip('\n')
            varValuelist = varValuelist.split(' ')
            for x in varValuelist:
                if (x != '') and (x[:1] != "|"):
                    toAdd = "PARAMS:: " + x
                    if toAdd not in keywords:
                        keywords.append(toAdd)
        elif 'ParameterBinding(Invoke-Expression)'.casefold() in line.casefold():
            varValue = line.split('value=', 1)[1].strip('"')
            varValue = varValue.strip('"\n')
            if varValue != '':
                toAdd = "IEX:: " + varValue
                if toAdd not in keywords:
                    keywords.append(toAdd)
        elif 'ParameterBinding('.casefold() in line.casefold():
            varValue = line.split('value=', 1)[1].strip('"')
            varValue = varValue.strip('"\n')
            if varValue != '':
                toAdd = "OTHERS:: " + varValue
                if toAdd not in keywords:
                    keywords.append(toAdd)

    return sorted(keywords, key=lambda keywords: keywords[0], reverse=False)



def MatchDictionary(key, regexpattern):
    FILE_PATH_DICTJSON = '%s/%s' % (WORKING_DIR, 'dictionary.json')
    dictionary = ReadDictJson(FILE_PATH_DICTJSON)
    for k in dictionary[key]:
        # print (k)
        # print ("regex this: " + regexpattern)
        if (re.search(regexpattern, k)):
            # print (regexpattern + " : " + (dictionary[i][k]))
            return (dictionary[key][k])

def WriteCSVHeader(FILE_PATH_ANALYSIS):
    """Call this ONCE to initialize CSV FIELD NAMES"""
    # CWD = os.getcwd()
    csvdict = {}
    # FILE_PATH_CSV = '%s/%s' % (CWD, 'analysis.csv')
    with open(FILE_PATH_ANALYSIS, 'a+', newline='') as f:
        fieldnames = ['TYPE', 'KEYWORDS', 'DESCRIPTION']
        writer = csv.DictWriter(f, fieldnames = fieldnames)
        writer.writeheader()


def WriteOutCSV(a, b, c):
    """CSV OUTPUT WRITER using 3 fields"""
    csvdict = {}
    FILE_PATH_CSV = '%s/%s' % (WORKING_DIR, 'analysis.csv')
    with open(FILE_PATH_CSV, 'a', newline='') as f:
        fieldnames = ['TYPE', 'KEYWORDS', 'DESCRIPTION']
        writer = csv.DictWriter(f, fieldnames = fieldnames)
        csvdict['TYPE'] = a
        csvdict['KEYWORDS'] = '"' + b + '"'
        csvdict['DESCRIPTION'] = c
        print ('{0:<35}'.format(bcolors.GREY + bcolors.BOLD + "TYPE: " + bcolors.ENDC + csvdict['TYPE']),
               '{:<70}'.format(bcolors.GREY + bcolors.BOLD + "KEYWORDS: " + bcolors.ENDC + csvdict['KEYWORDS']),
               '{:<100}'.format(bcolors.GREY + bcolors.BOLD + "DESCRIPTION: " + bcolors.ENDC + csvdict['DESCRIPTION']))
        writer.writerow(csvdict)

def WriteScriptBlockTxt(sbparseroutput):
    try:
        FILE_PATH_SCRIPTBLOCKTXT = '%s/%s' % (WORKING_DIR, 'scriptblock.txt')
        with open(FILE_PATH_SCRIPTBLOCKTXT, 'w', newline='') as f:
            f.write(str(sbparseroutput))
            f.close()
    except IOError as e:
        print (e)
        print ("IOError: Unable to open ", f)
        exit(1)

def scanArtifacts(capturedScript):
    try:
        FILE_PATH_DICTJSON = '%s/%s' % (WORKING_DIR, 'dictionary.json')
        out ="\n\nGathered ARTIFACTS: Modules\n"
        with open(FILE_PATH_DICTJSON, "r") as myfile:
            data = json.loads(myfile.read(), object_pairs_hook=OrderedDict)
        for artiType in data["ARTIFACTS"]:
            # print (artiType)
            #regx = re.compile(str(artiType), re.IGNORECASE)
            #if regx.search(str(capturedScript)):
            if str(artiType).casefold() in str(capturedScript).casefold():
                out = out + (artiType + ": "+data["ARTIFACTS"][artiType] + "\n")
                WriteOutCSV("SCRIPT_ARTIFACTS", artiType, data["ARTIFACTS"][artiType])
        return out
    except Exception as e:
        return e

def CollectArtifacts(regxR, capturedScript, description):
    #URL SHELLCODE BASE64
    try:
        out=""
        regx = re.compile(regxR, re.IGNORECASE)
        allArtifact = regx.findall(capturedScript)
        for arti in sorted(set(allArtifact)):
            out = out + str(arti) + "\n"
            WriteOutCSV("IOC", str(arti), description)
        return out
    except Exception as e:
        return e

def isscriptblockComplete(scriptblockMessage):
    regxScriptnumber = re.compile('Creating Scriptblock text \((\d*) of (\d*)\)\:')
    pages = regxScriptnumber.findall(scriptblockMessage)
    return pages[0][0] == pages[0][1]



def scriptblockCleanup(scriptblockMessage):
    regx1 = re.compile('Creating Scriptblock text \(\d* of \d*\)\:\r\n')
    regx2 = re.compile('\r\n\r\nScriptBlock ID\:.*\r\nPath:.*$')
    scriptblockMessage = regx1.sub('',scriptblockMessage)
    scriptblockMessage = regx2.sub('',scriptblockMessage)
    return scriptblockMessage



def scriptblockParser(FILE_PATH_4104):
    data = ReadJson(FILE_PATH_4104)
    # if TRUE it means 4104.txt was not found
    if (data == True): return data

    f_out ="\nPrinting Layers of ScriptBlocks:\n"
    out=""
    counter=1
    SBhead = "\nScriptBlock# "

    for sbMessage in data:

        temp = sbMessage['Message']
        completeSB = isscriptblockComplete(temp)

        #remove redundant code or first scriptblock and global parameter
        temp = scriptblockCleanup(temp)
        if  (temp in f_out) or \
            ("$global:?" in temp) or \
            ("Set-StrictMode -Version 1;" in temp) or \
            ("$this.TotalProcessorTime.TotalSeconds" in temp) or \
            ("$myinv = $_.InvocationInfo" in temp):
            continue

        out += temp

        if (completeSB):
            f_out = f_out + SBhead + str(counter) + ":\n" + out +"\n"
            counter = counter + 1
            out =""
    print (f_out)
    return f_out



def ProduceAnalysis(keywords):
    items = []
    regexpattern = ''
    for elem in keywords:
        items = elem.split(":: ")
        if (items[0] == "PARAMS"):
            try:
                regexpattern = re.compile("^"+items[1], re.IGNORECASE)
            except:
                continue
            xresult = MatchDictionary(items[0], regexpattern)
            if xresult == None: continue
            WriteOutCSV(items[0], items[1], xresult)
            # print (items[0])
            # print (items[1])
            # print (xresult)

        elif (items[0] == "COMMAND"):# or (items[0] == "OTHERS"):
            items[0] = "COMMAND"
            try:
                regexpattern = re.compile(items[1], re.IGNORECASE)
            except:
                continue
            xresult = MatchDictionary(items[0], regexpattern)
            if xresult == None: continue
            WriteOutCSV("CMDLET", items[1], xresult)

        elif (items[0] == "ADD-TYPE"):
            try:
                regexpattern = re.compile(items[1], re.IGNORECASE)
            except:
                continue
            xresult = MatchDictionary(items[0], regexpattern)
            if xresult == None: continue
            WriteOutCSV("ADD-TYPE", items[1], xresult)

        elif (items[0] == "NEW-OBJECT"):
            try:
                if str(items[1]).casefold() == "byte[]".casefold():
                    regexpattern = re.compile("byte[\[\]]", re.IGNORECASE)
                else:
                    regexpattern = re.compile(items[1], re.IGNORECASE)
            except:
                continue
            xresult = MatchDictionary(items[0], regexpattern)
            if xresult == None: continue
            WriteOutCSV(items[0], items[1], xresult)

        elif (items[0] == "PROCESS"):
            WriteOutCSV("CREATE PROCESS", items[1], "Attempts to execute the following process.")
        elif (items[0] == "REMOVE"):
            WriteOutCSV("REMOVE-ITEM", items[1], "Attempts to delete the following file or folder.")
        elif (items[0] == "TEST-PATH"):
            WriteOutCSV("TEST-PATH", items[1], "Checks if specified file exists")
        elif (items[0] == "IEX"):
            WriteOutCSV("Invoke-Expression", items[1], "Invokes the following expression")


def ReadConfig(fPATH):
    try:
        config = configparser.ConfigParser()
        config.read(fPATH)
        return config
    except Exception as e:
        print("Could not Access PEA.INI...Exiting")
        SystemExit(1)

def printLoading(Addstring, timerToStop):
    iterations = 101
    incrementer = timerToStop / iterations
    tstep = dt.timedelta(seconds=incrementer)
    for n in np.arange(iterations):
        startTime = dt.datetime.now()
        hash = ((60 * n) // 100)
        print("\r" + Addstring + "{}{} {}%".format('█' * hash, ' ' * (60 - hash), n), end="")
        while dt.datetime.now() < startTime + tstep:
            1 == 1
# if __name__ == "__main__":
#     print ("test")