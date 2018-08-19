#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user.
#Status: In development
#Bugs: Can't write to .ini because configState is only populated at runtime

from getmac import get_mac_address
from utils import FileIO, MacLookup
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
        self.config = FileIO.read_Config(self)
        [self.addrQueue.put(i) for i in[self.config['IP_PREFIX'][0] +'.'+ self.config['IP_PREFIX'][1] +'.'+ str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]
        self.recordList = []
        self.build_GUI()

    '''Draw GUI elements'''
    def build_GUI(self):
        ''''File menu'''''
        menubar = tk.Menu(root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Configure", command=self.config_Window)
        file_menu.add_command(label="About", command=self.about_Window)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        root.config(menu=menubar)

        '''Thread slider'''
        thread_slider = tk.Scale(self.master, from_=1, to=self.MAX_THREADS, resolution=8, length=300, orient='horizontal')
        thread_slider.grid(row=1, column=1)

        thread_label = tk.Label(self.master, text="Threads")
        thread_label.grid(row=2, column=1)

        '''Start/Stop buttons'''
        start_button = tk.Button(self.master, text="Start", command=lambda: self.start_Scan(thread_slider.get()))
        start_button.grid(row=3, column=0)

        stop_button = tk.Button(self.master, text="Stop", command=lambda: self.stop_Scan())
        stop_button.grid(row=3, column=2)

    '''Program description window'''
    def about_Window(self):
        about_win = tk.Toplevel()
        about_win.wm_title("About")
        about_label = tk.Label(about_win, text="NetMon 2018\n A multithreaded pinging tool designed to monitor for\n new connections to a network and generate basic reports.")
        about_label.grid(row=0, column=0)
        about_win.geometry('325x70')
        about_win.transient(self.master) #Only one window in taskbar
        about_win.grab_set() #Modal

    def config_Window(self):
        configState = {}

        config_win = tk.Toplevel()
        config_frame = tk.Frame(config_win)
        config_win.wm_title("Configuration")
        config_label = tk.Label(config_frame, text="<<<Configuration>>>").pack(side='top')
        config_frame.grid(row=0, column=0)

        '''IP Prefix'''
        ip_frame = tk.Frame(config_win)
        ip_desc_label = tk.Label(ip_frame, text="Enter prefix of network ").pack(side='left')
        prefix1_val = tk.StringVar()
        prefix2_val = tk.StringVar()

        prefix1_val.set(self.config['IP_PREFIX'][0]) #Set values from ini file
        prefix2_val.set(self.config['IP_PREFIX'][1])
        ip_prefix_form1 = tk.Entry(ip_frame, textvariable=prefix1_val, width=5).pack(side='left')
        dot = tk.Label(ip_frame, text=" . ").pack(side='left')
        ip_prefix_form2 = tk.Entry(ip_frame, textvariable=prefix2_val, width=5).pack(side='left')
        ip_suffix = tk.Label(ip_frame, text=" . X . X").pack(side='left')
        ip_frame.grid(row=1, column=0)

        '''Reports'''
        report_frame = tk.Frame(config_win)
        report_label = tk.Label(report_frame, text="Report frequency ").pack(side='left')
        reportFrequency = ['Live', '1 hour', '6 hours', '12 hours', '24 hours', 'Never']
        freqChoice = tk.StringVar(root)
        freqChoice.set(self.config['REPORT'])
        freqMenu = tk.OptionMenu(report_frame, freqChoice, *reportFrequency).pack(side='left')
        report_frame.grid(row=2, column=0)

        config_win.geometry('270x100')
        config_win.transient(self.master)  # Only one window in taskbar
        #config_win.grab_set()  # Modal

        '''Save Button'''
        save_button = tk.Button(config_win, text="Save", command=lambda: (self.save_Config(prefix1_val.get(), prefix2_val.get(), freqChoice.get()), config_win.destroy()))
        save_button.grid(row=3, column=0)

    '''Using 16-bit IPv4 scheme (after a successful ping, arp -a command can be run)'''
    def scan_Network(self):
        while not self.addrQueue.empty() and self.runScan:
            addr = self.addrQueue.get()
            try:
                response = os.system("ping -n 1 " + addr + ' > nul')
                mac = get_mac_address(ip=addr) #Throws runtime warning after first set of threads completes..?
                if response == 0 and mac:
                    oui = MacLookup.retrieve_OUI(self, mac)
                    print(addr, 'is up!', '\tMAC: ', mac, '\tInfo: ', oui, flush=True)
                    record = Record()
                    record.ip = addr
                    record.mac = mac
                    record.oui = oui
                    self.recordList.append(record)
                    FileIO.build_Report(self, self.recordList) #Testing
                else:
                    pass
                    # self.alert_User()
                    # print(addr, 'is down!', flush=True)
            except:
                print('Error during scan')
            self.addrQueue.put(addr)

    '''Create multiple threads to accelerate pinging'''
    def start_Scan(self, THREAD_COUNT):
        print('Starting scan..', flush=True)
        self.runScan = True
        self.threads = {}
        for i in range(0, THREAD_COUNT):
            self.threads['thread' + str(i)] = threading.Thread(target=self.scan_Network)  # Create thread
            self.threads['thread' + str(i)].start()  # Start thread

    '''Cancel current scan'''
    def stop_Scan(self):
        print('Stopping scan..', flush=True)
        self.runScan = False
        #self.master.quit()

    '''Update config.ini (perform checks on values here?)'''
    def save_Config(self, ip_prefix1, ip_prefix2, report_frequency):
        configState = {}
        try:
            if 0 < int(ip_prefix1) < 256 and 0 < int(ip_prefix2) < 256:
                configState['OCTET_ONE'] = 'IP_PREFIX', ip_prefix1
                configState['OCTET_TWO'] = 'IP_PREFIX', ip_prefix2
                self.addrQueue.queue.clear() #Clear existing queue
                [self.addrQueue.put(i) for i in[ip_prefix1 + '.' + ip_prefix2 + '.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]] #Rebuild IP Queue

            else:
                print("Please enter valid integers 0 < n < 256")
            configState['FREQUENCY'] = 'REPORT', report_frequency
            FileIO.write_Config(self, configState) #Write changes
            self.config = FileIO.read_Config(self)  # Read changes back
        except:
            print('Error while saving')

    '''Send email to user'''
    def alert_User(self):
        print("Emailing user..")


'''Record object'''
class Record():
    def __init__(self):
        self.ip = '0.0.0.0'
        self.mac = '00:00:00:00:00:00'
        self.oui = None


root = tk.Tk()
app = NetworkMonitor(root)
root.mainloop()