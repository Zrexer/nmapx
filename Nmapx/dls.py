import wget 
import platform
import time
import os

# Downloader class with OS Scanner
class DownloaderStream(object):
    def __init__(self):
        self.windows = "https://nmap.org/dist/nmap-7.94-setup.exe"
        self.linux = "https://nmap.org/dist/nmap-7.94-1.x86_64.rpm"
        self.mac = "https://nmap.org/dist/nmap-7.94.tar.bz2"
        self.db = {}
    
    def nmap(self, os_platform: str = platform.system()):
        self.db['download_time'] = time.ctime(time.time())
        self.db['os_platform'] = os_platform
        self.db['path_worker'] = os.getcwd()

        # Windows os 
        if os_platform == "Windows":
            try:
                wget.download(self.windows)
                os.system("cls || clear")
                self.db['error'] = False
                self.db['file_name'] = wget.filename_from_url(self.windows)
                return self.db
            except Exception as ERROR_WIN_DOWNLOAD:
                self.db['error'] = True
                self.db['base'] = str(ERROR_WIN_DOWNLOAD)
                return self.db
        
        # Linux os
        elif os_platform == "Linux":
            try:
                wget.download(self.linux)
                os.system("cls || clear")
                self.db['error'] = False
                self.db['file_name'] = wget.filename_from_url(self.linux)
                return self.db
            except Exception as ERROR_LINUX_DOWNLOAD:
                self.db['error'] = True
                self.db['base'] = str(ERROR_LINUX_DOWNLOAD)
                return self.db

        # Darwin => Mac os
        elif os_platform == "Darwin":
            try:
                wget.download(self.mac)
                os.system("cls || clear")
                self.db['error'] = False
                self.db['file_name'] = wget.filename_from_url(self.mac)
                return self.db
            except Exception as ERROR_MAC_DOWNLOAD:
                self.db['error'] = True
                self.db['base'] = str(ERROR_MAC_DOWNLOAD)
                return self.db
