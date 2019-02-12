import subprocess
import PeaHelper
import os

WORKING_DIR = os.path.dirname(os.path.realpath(__file__))
PEA_INI_LOC = WORKING_DIR + '/Pea.ini'

# sanitychecks
if not os.path.exists(PEA_INI_LOC):
    print("ERROR: Make sure PEA.INI is within PEA FOLDER")
    exit(1)
config = PeaHelper.ReadConfig(PEA_INI_LOC)

vmrun = str(config['VMWARE_SETTINGS']['VMRUN'])
# VMRUN PATH check
if not os.path.exists(vmrun.rstrip("\"").lstrip("\"")):
    print("ERROR: Double check VMRUN PATH?? --> ", vmrun)
    exit(1)

vmpath = str(config['VMWARE_SETTINGS']['VMPATH'])
# VMX PATH check
if not os.path.exists(vmpath.rstrip("\"").lstrip("\"")):
    print("ERROR: Double check VMX PATH?? --> ", vmpath)
    exit(1)

snapshot = str(config['VMWARE_SETTINGS']['SNAPSHOT'])
nogui = config['VMWARE_SETTINGS'].getboolean('NOGUI')
gusername = str(config['VMWARE_SETTINGS']['GUEST_USERNAME'])
gpassword = str(config['VMWARE_SETTINGS']['GUEST_PASSWORD'])
vmcreds = "-T ws -gu " + gusername + " -gp " + gpassword
runtimeVMGuest = config['VMWARE_SETTINGS'].getint('SAMPLERUNTIME')



def CopyFileHostToGuest(HostPath, GuestPath):
    HostToGuest = vmrun + ' ' + vmcreds + ' copyFileFromHostToGuest ' + vmpath + ' "' + HostPath + '" ' + GuestPath
    p = subprocess.Popen(HostToGuest, shell=True, stdout=subprocess.PIPE)
    p.wait()
    res = p.communicate()
    if (p.returncode == 255):
        print()
        print("Something went wrong.")
        print("ErrorCode=",p.returncode)
        print("Check ERROR: ", res)
        return (p.returncode)
    return 0

def VMGuestRevert():
    VMRevert = vmrun + ' ' + vmcreds + ' revertToSnapshot ' + vmpath + ' ' + snapshot
    p = subprocess.Popen(VMRevert,shell=True, stdout=subprocess.PIPE)
    p.wait()
    res = p.communicate()
    if (p.returncode == 255):
        print()
        print("Something went wrong.")
        print("ErrorCode=", p.returncode)
        print("Check ERROR: ", res)
        return (p.returncode)
    return 0

def VMGuesStart():
    if nogui:
        VMStart = vmrun + ' ' + vmcreds + ' start ' + vmpath + ' nogui'
    else:
        VMStart = vmrun + ' ' + vmcreds + ' start ' + vmpath
    p = subprocess.Popen(VMStart, shell=True, stdout=subprocess.PIPE)
    p.wait()
    res = p.communicate()
    if (p.returncode == 255):
        print()
        print("Something went wrong.")
        print("ErrorCode=", p.returncode)
        print("Check ERROR: ", res)
        return(p.returncode)
    return 0

def VMGuestStop():
    VMStop = vmrun + ' ' + vmcreds + ' stop ' + vmpath + ' hard'
    p = subprocess.Popen(VMStop, shell=True, stdout=subprocess.PIPE)
    p.wait()
    res = p.communicate()
    return 0

def VMGuestRunProg(GuestProg):
    VMRunProg = vmrun + ' ' + vmcreds + ' runProgramInGuest ' + vmpath + ' -interactive -activeWindow ' + GuestProg
    p = subprocess.Popen(VMRunProg, shell=True, stdout=subprocess.PIPE)
    p.wait()
    res = p.communicate()
    if p.returncode == 255:
        print()
        print("Something went wrong.")
        print("ErrorCode=", p.returncode)
        print("Check ERROR: ", res)
        return p.returncode
    return 0

def VMGuestRunSample(GuestProg):
    VMRunProg = vmrun + ' ' + vmcreds + ' runProgramInGuest ' + vmpath + ' -interactive -activeWindow ' + GuestProg
    p = subprocess.Popen(VMRunProg, shell=True)
    # i = runtimeVMGuest
    Addstr = "Executing Sample:         "
    PeaHelper.printLoading(Addstr, runtimeVMGuest)
    print("\n")


def VMCopyFileGuestToHost(GuestPath, HostPath):
    HostToGuest = vmrun + ' ' + vmcreds + ' copyFileFromGuestToHost ' + vmpath + ' "' + GuestPath + '" ' + HostPath
    p = subprocess.Popen(HostToGuest, shell=True, stdout=subprocess.PIPE)
    p.wait()

#if __name__ == "__main__":
#    print ("test")

