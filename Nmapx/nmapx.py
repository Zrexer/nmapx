#!/usr/bin/env python3 

from rich import print as printer
import os
import sys
import json
import platform
import time
import dls

# For Buffer Argv
commands: dict = {}

# Copied From my Github: https://github.com/Zrexer/JsonRipper/blob/main/src/JsonRipper.py
class JsonRipper(object):
    def __init__(self, __data = None):
        self.data = __data
    
    def console_log(self):
        printer(json.dumps(self.data, indent=4).replace("true", "True").replace("false", "False"))

    def parse(self, default: bool = True) -> str:
        if default == True:
            return json.dumps(self.data, indent=4)
        else:
            return json.dumps(self.data, indent=4).replace("true", "True").replace("false", "False")

# Copied From my Github: https://github.com/Zrexer/Bufferx
class BufferList(object):
    def __init__(self,
                 List: list = [],
                 ):
        
        self.list = List
        
    def parse(self):
        bfd = {}

        for i in range(len(self.list)):
            bfd["_"+str(i+1)] = self.list[i]

        return bfd
    
    def isexists(self, target):
        if target in self.list:
            return True
        else:return False
    
    def indexexists(self, target):
        if target in self.list:
            return self.list.index(target)
        else:return False

    def isinfrontof(self, target, indexes):
        isit = False

        if target in self.list:
            try:
                indx = self.list.index(target)
                if indx == indexes:
                    isit = True
                else:isit = False
            except Exception as e:return e
        
        return isit

# Copied From my Github: https://github.com/Zrexer/Bufferx
class BufferConsole(object):
    def __init__(self):

        self.data = []

    def __setcommands__(self, __key, __value):
        commands[__key] = __value
        return commands
    
    def getDictArgv(self):
        return BufferList(sys.argv).parse()
    
    def addFlag(self, *flags, mode: str = "in_front_of"):
        flg = list(flags)
        for i in range(len(flg)):
            self.__setcommands__(str(i+1), flg[i])

        if mode == "in_front_of":
            for key, val in BufferConsole().getDictArgv().items():
                if str(val) in flg:
                    keyx = int(str(key).replace("_", ""))
                    keyx += 1
                    if not f"_{keyx}" in BufferConsole().getDictArgv().keys():
                        self.data.append("Null")
                        pass
                    else:
                        self.data.append(BufferConsole().getDictArgv()[f"_{keyx}"])
                        pass
                
                else:
                    pass

            return self.data

# Scanner Options class
# Forwarded from the Nmap Switches
class Nmapx(object):
    """
    The Base Class
    ~~~~~~~~~~~~~~~
    Check Requirements:
    --------------------
    ```
    from Nmapx.builder import nmapx

    host = "example.com"
    port = 8080

    # For Check Requirements with Dictionary Output
    # If you Use Nmapx as Library, 'raiser' parameter should be True => default is true

    result = nmapx.__check_exists__(raiser = False)
    
    if result['error'] == True:
        print(f"Error Detected: {result['base']}")
    ```
    for Download Requirements:
    ---------------------------
    ```
    from Nmapx.dls import DownloaderStream as DLS

    DLS.nmap()
    ```
    """
    def __init__(self, nmap_path: str = None) -> None:
        self.nfp = nmap_path
        self.returner_data = {}

    # Check Nmap Does Exists and Download that if Not
    def __check_exists__(self, raiser: bool = True):
        """
        for Download Requirements
        ---------------------------
        if Client does not Have that:
        ```
        from Nmapx.dls import DownloaderStream as DLS

        DLS.nmap()
        ```
        """
        self.returner_data['check_time'] = time.ctime(time.time())
        if not os.path.exists(self.nfp):
            if raiser == True:
                raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
            else:
                self.returner_data['error'] = True
                self.returner_data['base'] = "The '{}' Does not Exists".format(self.nfp)
                return self.returner_data
        else:
            if not raiser == True:
                self.returner_data['error'] = False
                return self.returner_data
    
    # Simple Scan
    def regularScan(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "regular_scan"
                    self.returner_data['command'] = ""
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_RS:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_RS)
                    return self.returner_data

    # comprehensive Scan
    # -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"
    def compreScan(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f'{self.nfp} -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" {hostname}')
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "comprehensive_scan"
                    self.returner_data['command'] = '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"'
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data

    # Quick Traceout Scan
    # -sn --traceroute   
    def quickTraceout(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -sn --traceroute {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "quickTraceout_scan"
                    self.returner_data['command'] = "-sn --traceroute"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data
                
    # Quick Scan
    # -T4 -F
    def quickScan(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    
                    starter = time.time()
                    os.system(f"{self.nfp} -T4 -F {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "quick_scan"
                    self.returner_data['command'] = "-T4 -F"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data
                
    # Quick Scan Plus
    # -sV -T4 -O -F --version-light
    def quickScanPlus(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -sV -T4 -O -F --version-light {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "quick_scan_plus"
                    self.returner_data['command'] = "-sV -T4 -O -F --version-light"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data
                
    # Ping Scan
    # -sn
    def pingScan(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -sn {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "ping_scan"
                    self.returner_data['command'] = "-sn"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data
    
    # Intense Scan
    # -T4 -A -v
    def intenseScan(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -T4 -A -v {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "intense_scan"
                    self.returner_data['command'] = "-T4 -A -v"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data

    # Intense scan, no ping
    # -T4 -A -v -Pn
    def intenseScan_noping(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -T4 -A -v -Pn {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "intenseScan_noping"
                    self.returner_data['command'] = "-T4 -A -v -Pn"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data
    
    # Intense scan, all TCP ports
    # -p 1-65535 -T4 -A -v
    def intenseScan_allTcpPorts(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -p 1-65535 -T4 -A -v {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "intenseScan_allTcpPorts"
                    self.returner_data['command'] = "-p 1-65535 -T4 -A -v"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data
    
    # Intense Scan of UDP
    # -sS -sU -T4 -A -v
    def intenseScan_UDP(self, hostname: str = None):
        res = Nmapx(self.nfp).__check_exists__(False)
        self.returner_data.clear()
        self.returner_data['run_time'] = time.ctime(time.time())

        if 'error' in res.keys() and res['error'] == True:
            raise FileExistsError("The '{}' Does not Exists".format(self.nfp))
        else:
            if hostname == None:
                raise ValueError("The Hostname ('hostname') parameter cannot be Empty or None")
            else:
                try:
                    starter = time.time()
                    os.system(f"{self.nfp} -sS -sU -T4 -A -v {hostname}")
                    ender = time.time()
                    self.returner_data['error'] = False
                    self.returner_data['hostname_target'] = hostname
                    self.returner_data['method'] = "intenseScan_UDP"
                    self.returner_data['command'] = "-sS -sU -T4 -A -v"
                    self.returner_data['scanned_in'] = f"{ender-starter:.2f}"
                    return self.returner_data
                except Exception as ERROR_CPRES:
                    self.returner_data['error'] = True
                    self.returner_data['base'] = str(ERROR_CPRES)
                    return self.returner_data


# Commandline Setup Values
seter = BufferConsole().addFlag("--set")
check_seter = BufferConsole().addFlag("--check-set")
regular = BufferConsole().addFlag("-r")
comprehensive = BufferConsole().addFlag("--compre")
quickTrace = BufferConsole().addFlag("-qto")
quickS = BufferConsole().addFlag("-qs")
quickSP = BufferConsole().addFlag("-qsp")
pingS = BufferConsole().addFlag("-ps")
intenseS = BufferConsole().addFlag("--ins")
intenseSNP = BufferConsole().addFlag("--ins-np")
intenseSTCP = BufferConsole().addFlag("--ins-tcp")
intenseSUDP = BufferConsole().addFlag("--ins-udp")
dl = BufferConsole().addFlag("--dls")

# All Available Commands => Variable
console_commands_list = [["-h", "--help"], "--set", "--check-set", "-r", "-compre", "-qto", "-qs", "-qsp", "-ps", "--ins", "--ins-np", "--ins-tcp", "--ins-udp", "--dls"]

console_commands_dict = {
    "-h / --help" : "Show This Message",
    "--set" : "For Set the Path of Nmap Binary File and Save in a File",
    "--check-set" : "For Check the Exists file for Path of Nmap Binary File",
    "-r" : "regular scan",
    "--compre" : "Comprehensive Scan",
    "-qto" : "Quick Traceout Scan",
    "-qs" : "Quick Scan",
    "-qsp" : "Quick Scan Plus",
    "-ps" : "Ping Scan",
    "--ins" : "Intense Scan",
    "--ins-np" : "Intense Scan No Ping",
    "--ins-tcp" : "Intense Scan all TCP Ports",
    "--ins-udp" : "Intense Scan UDP Ports",
    "--dls" : "Download the nmap"
}

lis = sys.argv


if "-h" in lis or "--help" in lis:
    if "--dict" in lis:
        printer(console_commands_dict)
    
    elif "--list" in lis:
        printer(JsonRipper(console_commands_list).parse())
    
    else:
        printer(console_commands_dict)

if len(seter) == 1:
    if not seter[0] == 'Null':
        res = Nmapx(seter[0]).__check_exists__(False)
        if 'error' in res.keys() and res['error'] == True:
            print(f"Error: {res['base']}")
        else:
            try:
                if not os.path.exists("path_saver.json"):
                    data = json.dumps({"nmap_path" : seter[0]}, indent=4)
                    file = open("path_saver.json", "a")
                    file.write(data)
                    file.close()
                    printer({"writed" : True, "error" : False, "file_name" : "path_saver.json", "saved_in" : os.getcwd(), "data_writed" : data})
                else:
                    dataWriter = open("path_saver.json", "w")
                    mainData = json.dumps({"nmap_path" : seter[0]}, indent=4)
                    dataWriter.write(mainData)
                    printer({"writed" : True, "error" : False, "file_name" : "path_saver.json", "saved_in" : os.getcwd(), "data_writed" : mainData})

            except Exception as ERROR_FILE_IO:
                printer({"error" : True, "base" : str(ERROR_FILE_IO)})
    else:
        printer("Cannot be Empty: \"--set <NMAP_BINARY_PATH_FILE>\"")

if len(check_seter) == 1:
    data = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in data.keys() and data['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
    else:
        reader = eval(open("path_saver.json", 'r').read())
        printer(f"File Does Exists and your nmap path is \"{reader['nmap_path']}\"")

if len(regular) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        if not regular[0] == "Null":
            data = eval(open("path_saver.json", 'r').read())
            Nmapx(data['nmap_path']).regularScan(regular[0])
        
        else:
            printer("Cannot be Empty: \"-r <HOSTNAME>\"")

if len(comprehensive) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not comprehensive[0] == "Null":
            Nmapx(data['nmap_path']).compreScan(comprehensive[0])
            
        else:
            printer("Cannot be Empty: \"--compre <HOSTNAME>\"")

if len(quickTrace) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not quickTrace[0] == "Null":
            Nmapx(datax['nmap_path']).quickTraceout(quickTrace[0])
            
        else:
            printer("Cannot be Empty: \"-qto <HOSTNAME>\"")

if len(quickS) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not quickS[0] == "Null":
            Nmapx(data['nmap_path']).quickScan(quickS[0])
    
        else:
            printer("Cannot be Empty: \"-qs <HOSTNAME>\"")

if len(quickSP) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not quickSP[0] == "Null":
            Nmapx(data['nmap_path']).quickScanPlus(quickSP[0])
        
        else:
            printer("Cannot be Empty: \"-qsp <HOSTNAME>\"")

if len(pingS) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not pingS[0] == "Null":
            Nmapx(data['nmap_path']).pingScan(pingS[0])
        
        else:
            printer("Cannot be Empty: \"-ps <HOSTNAME>\"")

if len(intenseS) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not intenseS[0] == "Null":
            Nmapx(data['nmap_path']).intenseScan(intenseS[0])
        
        else:
            printer("Cannot be Empty: \"--ins <HOSTNAME>\"")

if len(intenseSNP) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not intenseSNP[0] == "Null":
            Nmapx(data['nmap_path']).intenseScan_noping(intenseSNP[0])
        
        else:
            printer("Cannot be Empty: \"--ins-np <HOSTNAME>\"")

if len(intenseSTCP) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not intenseSTCP[0] == "Null":
            Nmapx(data['nmap_path']).intenseScan_allTcpPorts(intenseSTCP[0])
        
        else:
            printer("Cannot be Empty: \"--ins-tcp <HOSTNAME>\"")

if len(intenseSUDP) == 1:
    datax = Nmapx("path_saver.json").__check_exists__(False)
    if 'error' in datax.keys() and datax['error'] == True:
        printer("Cannot Find the 'path_saver.json', to add that you can use \"--set <NMAP_BINARY_PATH_FILE>\" to create and save your nmap file path")
        exit()

    elif 'error' in datax.keys() and datax['error'] == False:
        data = eval(open("path_saver.json", 'r').read())
        if not intenseSUDP[0] == "Null":
            Nmapx(data['nmap_path']).intenseScan_UDP(intenseSUDP[0])
        
        else:
            printer("Cannot be Empty: \"--ins-udp <HOSTNAME>\"")

if len(dl) == 1:
    oss = ["Windows", "Linux", "Darwin"]
    if dl[0] in oss:
        if dl[0] == "Windows":printer("Download For \"Windows\"");dls.DownloaderStream().nmap("Windows")
        elif dl[0] == "Linux":printer("Download For \"Linux\"");dls.DownloaderStream().nmap("Linux")
        elif dl[0] == "Darwin":printer("Download For \"Darwin\"");dls.DownloaderStream().nmap("Darwin")
    
    elif dl[0] == "--scan":
        printer(f"Your OS: \"{platform.system()}\"")
        dls.DownloaderStream().nmap()

    else:
        printer("Cannot get the OS")
        printer("Countinue with \"Windows\"")
        dls.DownloaderStream().nmap("Windows")
