#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user.
#Status: In development

from getmac import get_mac_address
from Library import FileOutput
import tkinter as tk
import warnings
import threading
import queue
import os

class NetworkMonitor():
    def __init__(self, master):
        self.master = master

        master.title('Network Monitor v0.1')
        warnings.filterwarnings("ignore") #Ignore warning from get-mac lib

        self.runScan = True
        self.MAX_THREADS = 128
        self.addrQueue = queue.Queue()
        [self.addrQueue.put(i) for i in['192.168.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]
        self.recordList = []

        self.build_GUI()

    '''Draw GUI elements'''
    def build_GUI(self):
        ''''File menu'''''
        menubar = tk.Menu(root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Configure", command=self.configure_Window)
        file_menu.add_command(label="About", command=self.about_Window)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        root.config(menu=menubar)

        '''Thread slider'''
        thread_slider = tk.Scale(self.master, from_=1, to=self.MAX_THREADS, resolution=8, length=300, orient='horizontal')
        thread_slider.grid(row=0, column=1)

        thread_label = tk.Label(self.master, text="Threads")
        thread_label.grid(row=1, column=1)

        '''Start/Stop buttons'''
        start_button = tk.Button(self.master, text="Start", command=lambda: self.start_Scan(thread_slider.get()))
        start_button.grid(row=2, column=0)

        stop_button = tk.Button(self.master, text="Stop", command=lambda: self.stop_Scan())
        stop_button.grid(row=2, column=2)

    '''Program description window'''
    def about_Window(self):
        about_win = tk.Toplevel()
        about_win.wm_title("About")
        about_label = tk.Label(about_win, text="NetMon 2018\n A multithreaded pinging tool designed to monitor for\n new connections to a network and generate basic reports.")
        about_label.grid(row=0, column=0)
        about_win.geometry('325x70')
        about_win.transient(self.master) #Only one window in taskbar
        about_win.grab_set() #Modal

    def configure_Window(self):
        config_win = tk.Toplevel()
        config_win.wm_title("Configuration")
        config_label = tk.Label(config_win, text="-----Report Configuration-----")
        config_label.grid(row=0, column=1)

        '''Reports'''
        report_label = tk.Label(config_win, text="Generate report every ")
        report_label.grid(row=1, column=1)

        '''Frequency drop-down'''
        tkVar = tk.StringVar(root)
        freqList = ['1 hour', '6 hours', '12 hours', '24 hours', 'Live']
        tkVar.set('1 hour')

        freqMenu = tk.OptionMenu(config_win, tkVar, *freqList)
        freqMenu.grid(row=1, column=2)

        '''Contact List'''

        config_win.geometry('400x150')
        config_win.transient(self.master)  # Only one window in taskbar
        #config_win.grab_set()  # Modal

    '''Using 16-bit IPv4 scheme'''
    def scan_Network(self):
        while not self.addrQueue.empty() and self.runScan:
            addr = self.addrQueue.get()
            try:
                if addr == '192.168.2.2':
                    print("STOP") #Testing
                    FileOutput.build_Report(self, self.recordList)

                response = os.system("ping -n 1 " + addr + ' > nul')
                mac = get_mac_address(ip=addr) #Throws runtime warning after first set of threads completes..?
                if response == 0 and mac:
                    print(addr, 'is up!', "\t MAC: ", mac, flush=True) #Testing

                    record = Record()
                    record.ip = addr
                    record.mac = mac
                    self.recordList.append(record)

                else:
                    pass
                    # self.alert_User()
                    # print(addr, 'is down!', flush=True)
            except:
                print('Error during scan')
            self.addrQueue.put(addr)

    '''Create multiple threads to accelerate pinging'''
    def start_Scan(self, THREAD_COUNT):
        self.runScan = True
        self.threads = {}
        for i in range(0, THREAD_COUNT):
            self.threads['thread' + str(i)] = threading.Thread(target=self.scan_Network)  # Create thread
            self.threads['thread' + str(i)].start()  # Start thread

    '''Cancel current scan'''
    def stop_Scan(self):
        self.runScan = False
        #self.master.quit()

    '''Send email to user'''
    def alert_User(self):
        print("Emailing user..")
        #self.stop_Scan() #Testing


'''Record object'''
class Record():
    def __init__(self):
        self.ip = '0.0.0.0'
        self.mac = '00:00:00:00:00:00'


root = tk.Tk()
app = NetworkMonitor(root)
#root.geometry('380x100')
root.mainloop()