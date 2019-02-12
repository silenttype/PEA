import PeaHelper
import PeaVM
import os
import time
import sys
import magic
import platform
import colorama


from pathlib import Path
###############################
# INITIALIZATIONS
###############################

OStype = platform.system()
colorama.init()

#regxArtifactsURL = '(?:(?:https?|ftp)://)?[$\.\w-]{2,256}\.(?:com|net|org)(?![\w\.])(?:[/][/\.\w-]+)?'
regxArtifactsURL = '(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}[-a-zA-Z0-9:%_\+.~#?&//=]*)'
regxArtifactsBASE64 = '(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
regxArtifactsBYTECODE = '((?:0x[A-F0-9]{1,2},?){20,})'
regxArtifactsIPadd = '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
regxArtifactsFile = '(?:[A-Za-z]\:)?[\\\.\w-]+\.(?:exe|dll|bat|vbs|ps1|php|pdf|html|js|txt|do[ct]|pdf|vsd|xl[st]|.p[op]t|mpp)'

WORKING_DIR = os.path.dirname(os.path.realpath(__file__))
if not os.path.exists(WORKING_DIR + '/eventlogs'): os.makedirs(WORKING_DIR + '/eventlogs')
FILE_PATH_4103 = '%s/%s' % (WORKING_DIR, 'eventlogs/4103.txt')
FILE_PATH_4104 = '%s/%s' % (WORKING_DIR, 'eventlogs/4104.txt')
FILE_PATH_SCRIPTBLOCK = '%s/%s' % (WORKING_DIR, 'scriptblock.txt')
FILE_PATH_ANALYSIS = '%s/%s' % (WORKING_DIR, 'analysis.csv')

# Parse Pea.ini
PEA_INI_LOC = WORKING_DIR + '/Pea.ini'
config = PeaHelper.ReadConfig(PEA_INI_LOC)
GUESTSAMPLE = str(config['VMWARE_GUEST']['SAMPLEFOLDER']).rstrip('"') + '\\sample'
PEAFOLDER = str(config['VMWARE_GUEST']['PEAFOLDER']).rstrip('"')
SAMPLETIMER = config['VMWARE_SETTINGS'].getint('SAMPLERUNTIME')
PSFILE = PEAFOLDER + '\\EventExtractor.ps1\"'
REGFILE = PEAFOLDER + '\\PS.reg\"'
ELEVATOR = PEAFOLDER + '\\ELEVATOR.bat\"' #yeah I know :))
RUNBAT = PEAFOLDER + '\\RUN.bat\"'
REGBAT = PEAFOLDER + '\\PSREG.bat\"'
FILE4103 = PEAFOLDER + '\\4103.txt\"'
FILE4104 = PEAFOLDER + '\\4104.txt\"'



def Banner():
    print('\033[H\033[J')

    print(PeaHelper.bcolors.YELLOW + " █" + PeaHelper.bcolors.BLUE + "█████╗  ██████╗ ██╗    ██╗███████╗██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗             ")
    print(PeaHelper.bcolors.YELLOW + " ██╔" + PeaHelper.bcolors.BLUE + "══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██║     ██║             ")
    print(PeaHelper.bcolors.YELLOW + " ██████" + PeaHelper.bcolors.BLUE + "╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝███████╗███████║█████╗  ██║     ██║             ")
    print(PeaHelper.bcolors.YELLOW + " ██╔═══╝ " + PeaHelper.bcolors.BLUE + "██║   ██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══██║██╔══╝  ██║     ██║             ")
    print(PeaHelper.bcolors.YELLOW + " ██║     ╚█" + PeaHelper.bcolors.BLUE + "█████╔╝╚███╔███╔╝███████╗██║  ██║███████║██║  ██║███████╗███████╗███████╗        ")
    print(PeaHelper.bcolors.YELLOW + " ╚═╝      ╚══" + PeaHelper.bcolors.BLUE + "═══╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝        ")
    print(PeaHelper.bcolors.YELLOW + " ███████╗██╗  █" + PeaHelper.bcolors.BLUE + "█╗████████╗██████╗  █████╗  ██████╗████████╗ ██████╗ ██████╗        ")
    print(PeaHelper.bcolors.YELLOW + " ██╔════╝╚██╗██╔╝" + PeaHelper.bcolors.BLUE + "╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗       ")
    print(PeaHelper.bcolors.YELLOW + " █████╗   ╚███╔╝   " + PeaHelper.bcolors.BLUE + " ██║   ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝       ")
    print(PeaHelper.bcolors.YELLOW + " ██╔══╝   ██╔██╗ " + PeaHelper.bcolors.RED + "   ██║   ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗       ")
    print(PeaHelper.bcolors.YELLOW + " ███████╗██╔╝ █" + PeaHelper.bcolors.RED + "█╗   ██║   ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║       ")
    print(PeaHelper.bcolors.YELLOW + " ╚══════╝╚═╝ " + PeaHelper.bcolors.RED + " ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝       ")
    print(PeaHelper.bcolors.YELLOW + " █████╗  ███" + PeaHelper.bcolors.RED + "╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗           ")
    print(PeaHelper.bcolors.YELLOW + " ██╔══██╗" + PeaHelper.bcolors.RED + "████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗          ")
    print(PeaHelper.bcolors.YELLOW + " ██████" + PeaHelper.bcolors.RED + "█║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝          ")
    print(PeaHelper.bcolors.YELLOW + " ██╔═" + PeaHelper.bcolors.RED + "═██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗          ")
    print(PeaHelper.bcolors.YELLOW + " ██" + PeaHelper.bcolors.RED + "║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║          ")
    print(PeaHelper.bcolors.YELLOW + " ╚" + PeaHelper.bcolors.RED + "═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝™ v.1.0   ")
    print("\n")
    print(PeaHelper.bcolors.WHITE + PeaHelper.bcolors.BOLD)
    print(PeaHelper.bcolors.BLACKBG + " by: silenttype & fakeJAVL                               ")
    print("\n\n" + PeaHelper.bcolors.ENDC)

def SampleSubmit(SAMPLE, GUESTSAMPLE):

    RETVALFAIL = 0
    while 1:
        print("REVERTING VM................", end='\r')
        if (0 != PeaVM.VMGuestRevert()):
            RETVALFAIL = 1
            break
        if (0 != PeaVM.VMGuesStart()):
            RETVALFAIL = 1
            break
        print("REVERTING VM................" + PeaHelper.bcolors.WHITE + "[DONE]" + PeaHelper.bcolors.ENDC)

        print("Setting up VM...............", end='\r')

        if (0 != PeaVM.CopyFileHostToGuest(WORKING_DIR + "/TOVM/RUN.bat", RUNBAT)):
            RETVALFAIL = 1
            break
        if (0 != PeaVM.CopyFileHostToGuest(WORKING_DIR + "/TOVM/EventExtractor.ps1", PSFILE)):
            RETVALFAIL = 1
            break
        # print("Copied to VM:" + PSFILE)
        if (0 != PeaVM.CopyFileHostToGuest(WORKING_DIR + "/TOVM/PS.reg", REGFILE)):
            RETVALFAIL = 1
            break
        # print("Copied to VM:" + REGFILE)
        if (0 != PeaVM.CopyFileHostToGuest(WORKING_DIR + "/TOVM/PSREG.bat", REGBAT)):
            RETVALFAIL = 1
            break
        # print("Copied to VM:" + ELEVATOR)
        if (0 != PeaVM.CopyFileHostToGuest(WORKING_DIR + "/TOVM/ELEVATOR.bat", ELEVATOR)):
            RETVALFAIL = 1
            break
        # print("Copied to VM:" + REGBAT)
        if (0 != PeaVM.VMGuestRunProg(ELEVATOR + ' ' + REGBAT)):
            RETVALFAIL = 1
            break
        print("Setting up VM..............." + PeaHelper.bcolors.WHITE + "[DONE]" + PeaHelper.bcolors.ENDC)

        print("Submitting Sample For Analysis: " + SAMPLE)
        if (0 != PeaVM.CopyFileHostToGuest('\"' + SAMPLE + '\"', GUESTSAMPLE)):
            RETVALFAIL = 1
            break
        time.sleep(1)
        print("Copied to VM as:" + GUESTSAMPLE)


        # Execute Sample in Guest VM
        PeaVM.VMGuestRunSample(RUNBAT + ' ' + GUESTSAMPLE)

        # Execute EventExtractor.ps1 in Guest VM twice
        if (0 != PeaVM.VMGuestRunProg(RUNBAT + ' ' + PSFILE)):
            RETVALFAIL = 1
            break
        # Execute EventExtractor.ps1 in Guest VM
        if (0 != PeaVM.VMGuestRunProg(RUNBAT + ' ' + PSFILE)):
            RETVALFAIL = 1
            break
        Addstr = "Collecting Information:   "
        PeaHelper.printLoading(Addstr, 10)
        print ("\n")

        if OStype == 'Windows':
            PeaVM.VMCopyFileGuestToHost(FILE4103, FILE_PATH_4103)
        else:
            PeaVM.VMCopyFileGuestToHost('"' + FILE4103 + '"', FILE_PATH_4103)
        Addstr = "Extracting File 4103.txt: "
        PeaHelper.printLoading(Addstr, 2)
        print ("\n")

        # temp watchdog timer,
        # because sometimes CopyFileGuestToHost takes a lot longer to finish
        watchdog = 0
        while not os.path.exists(FILE_PATH_4103):
            if watchdog == 9000000: break
            watchdog = watchdog + 1
        # print("4103 = ", watchdog)

        if OStype == 'Windows':
            PeaVM.VMCopyFileGuestToHost(FILE4104, FILE_PATH_4104)
        else:
            PeaVM.VMCopyFileGuestToHost('"' + FILE4104 + '"', FILE_PATH_4104)
        Addstr = "Extracting File 4104.txt: "
        PeaHelper.printLoading(Addstr, 2)
        print ("\n")

        # temp watchdog timer,
        # because sometimes CopyFileGuestToHost takes a lot longer to finish
        watchdog = 0
        while not os.path.exists(FILE_PATH_4104):
            if watchdog == 9000000: break
            watchdog = watchdog + 1
        # print ("4104 = ", watchdog)
        break

    print("\nStopping VM...")
    PeaVM.VMGuestStop()
    time.sleep(1)
    return RETVALFAIL


def AnalysisStart():
    print ("Starting Analysis...\n")
    # INITIALIZE CSV HEADERS
    PeaHelper.WriteCSVHeader(FILE_PATH_ANALYSIS)
    # PARSE 4104.txt
    scriptblocktxt = PeaHelper.scriptblockParser(FILE_PATH_4104)
    if (scriptblocktxt == True):
        print("Still continuing...\n")
    else:
        print("\n\nExtracting ScriptBlocks.........100%(DONE)")
        print(
            PeaHelper.bcolors.GREEN + "saved in " + PeaHelper.bcolors.BOLD + PeaHelper.bcolors.BLUE + FILE_PATH_SCRIPTBLOCK + PeaHelper.bcolors.ENDC)
        print("\n")
        PeaHelper.WriteScriptBlockTxt(str(scriptblocktxt))

        aTmp = scriptblocktxt.replace("`", "").replace("+", "").replace("''", "")

        PeaHelper.scanArtifacts(str(aTmp))
        PeaHelper.CollectArtifacts(regxArtifactsURL, str(aTmp),
                                                "May attempt to access or download from the following URLS.")
        PeaHelper.CollectArtifacts(regxArtifactsBASE64, str(aTmp),
                                                 "Suspicious Encoded string.")
        PeaHelper.CollectArtifacts(regxArtifactsBYTECODE, str(aTmp),
                                                "Possible shellcode.")
        PeaHelper.CollectArtifacts(regxArtifactsIPadd, str(aTmp),
                                                "May attempt to access or download from the following IP.")
        PeaHelper.CollectArtifacts(regxArtifactsFile, str(aTmp),
                                                "May attempt to access, create or execute the following file.")
    # PARSE 4103.txt
    keywords = PeaHelper.Read4103(FILE_PATH_4103)
    if (keywords == True):
        print("Still continuing...\n")
    else:
        PeaHelper.ProduceAnalysis(keywords)
        print("\n\nAnalyzing Extracted PowerShell Script.........100%(DONE)")
        print(
            PeaHelper.bcolors.GREEN + "saved in " + PeaHelper.bcolors.BOLD + PeaHelper.bcolors.BLUE + FILE_PATH_ANALYSIS + PeaHelper.bcolors.ENDC)
    if (scriptblocktxt == True and keywords == True):
        print("\nNO ANALYSIS CREATED!?")
        print("\nCheck any ERROR CODES or it is possible that the submitted sample did not execute PowerShell")
    print(PeaHelper.bcolors.BOLD + PeaHelper.bcolors.WHITE + "\nHappy PowerShell Hunting!" + PeaHelper.bcolors.ENDC)
    # print (keywords)

def IdentifyProperSuffix(SAMPLE):
    EXTENSION = ""
    EXTLIST = ['.EXE', '.DOC', '.DOCX', '.PDF', '.PPT', '.PPTX', '.XLS', '.XLSX', '.HTML', '.JS', '.VBS', '.PS1',
               '.BAT']
    if not os.path.exists(SAMPLE):
        # SANITY CHECK FOR SUBMITTED SAMPLE
        print("Verify that the submitted sample exists")
        raise SystemExit(1)
    else:
        # File extension is not included in the list
        # verify mimetype for consistency
        MIMETYPE = magic.from_file(SAMPLE, mime=True)
        print("Sample identified as: " + MIMETYPE)

        if MIMETYPE == "application/msword":
            EXTENSION = ".DOC"
        elif MIMETYPE == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            EXTENSION = ".DOCX"
        elif MIMETYPE == "application/x-dosexec":
            EXTENSION = ".EXE"
        elif MIMETYPE == "application/pdf":
            EXTENSION = ".PDF"
        elif MIMETYPE == "text/html":
            EXTENSION = ".HTML"
        elif MIMETYPE == "application/javascript":
            EXTENSION = ".JS"
        elif MIMETYPE == "application/vnd.ms-powerpoint":
            EXTENSION = ".PPT"
        elif MIMETYPE == "application/vnd.openxmlformats-officedocument.presentationml.presentation":
            EXTENSION = ".PPTX"
        elif MIMETYPE == "application/vnd.ms-excel":
            EXTENSION = ".XLS"
        elif MIMETYPE == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
            EXTENSION = ".XLSX"
        else:
            # If submitted sample is already renamed with proper file extension
            # no need to rename just submit directly
            for EXT in EXTLIST:
                if Path(SAMPLE).suffix.upper() == EXT:
                    EXTENSION = EXT
                    return EXTENSION

            # Unsupported filetype (text/plain) or .txt will fall under this category
            print("\nOoops!")
            print("This filetype seems to be not supported")
            print("If you've submitted a PowerShell script add .PS1 as its file extension then resubmit again,")
            print("Else if you've submitted a VBScript add .VBS as its file extension then resubmit again,")
            print("Bye! Exiting....")
            raise SystemExit(1)
    return EXTENSION


def CleanUpLogs():
    if (os.path.exists(FILE_PATH_SCRIPTBLOCK)): os.remove(FILE_PATH_SCRIPTBLOCK)
    if (os.path.exists(FILE_PATH_ANALYSIS)): os.remove(FILE_PATH_ANALYSIS)
    if (os.path.exists(FILE_PATH_4103)): os.remove(FILE_PATH_4103)
    if (os.path.exists(FILE_PATH_4104)): os.remove(FILE_PATH_4104)



if __name__ == "__main__":
    Banner()
    if (os.path.exists(FILE_PATH_ANALYSIS)): os.remove(FILE_PATH_ANALYSIS)

    if (len(sys.argv) == 2):
        # DO SOME CLEANUP FIRST
        CleanUpLogs()
        SAMPLE = (str(sys.argv[1]))

        EXTENSION = IdentifyProperSuffix(SAMPLE)
        GUESTSAMPLE = GUESTSAMPLE + EXTENSION + '"'

        ###############################
        # SAMPLE SUBMISSION START
        ###############################
        SUBMITSUCCESS = SampleSubmit(SAMPLE, GUESTSAMPLE)

        ##############################
        # ANALYSIS START
        ##############################
        if (SUBMITSUCCESS == 0):
            AnalysisStart()



    else:
        print("Extracts PowerShell and outputs Analysis")
        print("Usage: Pea.py <SAMPLE>")
        print("\n\n")

    raise SystemExit(0)