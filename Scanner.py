#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user.
#Status: In development
#Bugs:

from getmac import get_mac_address
from utils import FileIO, MacLookup
import tkinter as tk
import warnings
import threading
import queue
import os

class NetworkMonitor():
    warnings.filterwarnings("ignore")  # Ignore warning from get-mac lib

    def __init__(self, master):
        self.master = master
        master.title('Net Discovery Tool v0.1')
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
        thread_label = tk.Label(self.master, text="Threads")
        thread_label.grid(row=1, column=1, columnspan=3)

        thread_slider = tk.Scale(self.master, from_=1, to=self.MAX_THREADS, resolution=8, length=300, orient='horizontal')
        thread_slider.grid(row=2, column=1, columnspan=3)

        '''Start/Stop buttons'''
        button_frame = tk.Frame(self.master)
        start_button = tk.Button(button_frame, text="Start", command=lambda: self.start_Scan(thread_slider.get())).pack(side='left')
        stop_button = tk.Button(button_frame, text="Stop", command=lambda: self.stop_Scan()).pack(side='left')
        button_frame.grid(row=3, column=1, columnspan=3)

    '''Program description window'''
    def about_Window(self):
        about_win = tk.Toplevel()
        about_win.wm_title("About")
        about_label = tk.Label(about_win, text="NetMon 2018\n A multithreaded pinging tool designed to monitor for\n new connections to a network and generate basic reports.")
        about_label.grid(row=0, column=0)
        about_win.geometry('325x70')
        about_win.transient(self.master)  # Only one window in taskbar
        about_win.grab_set() #Modal

    def config_Window(self):
        config_win = tk.Toplevel()
        config_frame = tk.Frame(config_win)
        config_win.wm_title("Configuration")
        config_label = tk.Label(config_frame, text="<<<Configuration>>>").pack(side='top')
        config_frame.grid(row=0, column=0)

        '''IP Prefix Selection'''
        ip_frame = tk.Frame(config_win)
        ip_desc_label = tk.Label(ip_frame, text="Enter prefix of network ").pack(side='left')
        prefix1_val = tk.StringVar()
        prefix2_val = tk.StringVar()

        prefix1_val.set(self.config['IP_PREFIX'][0])  # Set values from ini file
        prefix2_val.set(self.config['IP_PREFIX'][1])
        ip_prefix_form1 = tk.Entry(ip_frame, textvariable=prefix1_val, width=5).pack(side='left')
        dot = tk.Label(ip_frame, text=" . ").pack(side='left')
        ip_prefix_form2 = tk.Entry(ip_frame, textvariable=prefix2_val, width=5).pack(side='left')
        ip_suffix = tk.Label(ip_frame, text=" . X . X").pack(side='left')
        ip_frame.grid(row=1, column=0)

        '''Reports'''
        report_frame = tk.Frame(config_win)
        report_label = tk.Label(report_frame, text="Report frequency ").pack(side='left')
        report_freq = ['Live', '1 hour', '6 hours', '12 hours', '24 hours', 'Never']
        freq_choice = tk.StringVar(root)
        freq_choice.set(self.config['REPORT'])
        freq_menu = tk.OptionMenu(report_frame, freq_choice, *report_freq).pack(side='left')
        report_frame.grid(row=2, column=0)

        '''Discovery Type'''
        discovery_frame = tk.Frame(config_win)
        report_label = tk.Label(discovery_frame, text="Discovery method ").pack(side='left')
        disc_choice = tk.StringVar(root)
        disc_choice.set(self.config['DISCOVERY'])
        disc_menu = tk.OptionMenu(discovery_frame, disc_choice, *['ARP', 'Ping']).pack(side='left')
        discovery_frame.grid(row=3, column=0)

        '''Save Button'''
        save_button = tk.Button(config_win, text="Save", command=lambda: (
            self.save_Config(prefix1_val.get(), prefix2_val.get(), freq_choice.get(), disc_choice.get()), config_win.destroy()))  # Could probably be cleaned up
        save_button.grid(row=4, column=0)

        config_win.transient(self.master)  # Only one window in taskbar
        config_win.grab_set()  # Modal

    '''Using 16-bit IPv4 scheme (after a successful ping, arp -a command can be run)'''
    def scan_Network(self, scanType):
        while not self.addrQueue.empty() and self.runScan:
            addr = self.addrQueue.get()
            try:
                if scanType == 'ARP':
                    arpOutput = []  # Move this somewhere outside of loop(?)
                    response = os.system('ping -n 1 ' + addr + ' > nul')
                    mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                    if response == 0 and mac:
                        print('Ping successful, running ARP command..', flush=True)
                        self.runScan = False  # Stop scan after successful ping
                        arp = os.popen('arp -a').read()
                        for i, val in enumerate(arp.split('\n')):
                            arpOutput.append(val.split())
                            if len(arpOutput[i]) == 3:
                                oui = MacLookup.retrieve_OUI(self, arpOutput[i][1])
                                record = Record()
                                record.ip = arpOutput[i][0]
                                record.mac = arpOutput[i][1]
                                record.type = arpOutput[i][2]
                                record.oui = oui
                                print('Discovered: ', 'IP: ', record.ip, 'MAC: ', record.mac, 'Type: ', record.type, 'Vendor: ', record.oui)
                                self.recordList.append(record)
                        FileIO.build_Report(self, self.recordList)  # Testing
                    else:
                        pass
                        # self.alert_User()
                        # print(addr, 'is down!', flush=True)

                if scanType == 'Ping':
                    response = os.system('ping -n 1 ' + addr + ' > nul')
                    mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                    if response == 0 and mac:
                        oui = MacLookup.retrieve_OUI(self, mac)
                        record = Record()
                        record.ip = addr
                        record.mac = mac
                        record.type = None  # Unavailable for this method
                        record.oui = oui
                        print(addr, 'is up!', '\tMAC: ', mac, '\tVendor: ', oui, flush=True)
                        self.recordList.append(record)
                        FileIO.build_Report(self, self.recordList)  # Testing
                    else:
                        pass
                        # self.alert_User()
                        # print(addr, 'is down!', flush=True)
            except:
                print('Error during scan')
            self.addrQueue.put(addr)

    '''Create multiple threads to accelerate pinging'''
    def start_Scan(self, threadCount):
        scanType = self.config['DISCOVERY']
        print('Discovering devices via brute force ping' if scanType == 'Ping' else 'Displaying Address Resolution Protocol (ARP) Table', flush=True)
        self.runScan = True
        self.threads = {}
        for i in range(0, threadCount):
            self.threads['thread' + str(i)] = threading.Thread(target=lambda: self.scan_Network(scanType))  # Create thread
            self.threads['thread' + str(i)].start()  # Start thread

    '''Cancel current scan'''
    def stop_Scan(self):
        print('Stopping scan..', flush=True)
        self.runScan = False
        #self.master.quit()

    '''Update config.ini (perform checks on values here?)'''
    def save_Config(self, ip_prefix1, ip_prefix2, report_freq, disc_choice):
        configState = {}
        try:
            if 0 < int(ip_prefix1) < 256 and 0 < int(ip_prefix2) < 256:
                configState['OCTET_ONE'] = 'IP_PREFIX', ip_prefix1
                configState['OCTET_TWO'] = 'IP_PREFIX', ip_prefix2
                self.addrQueue.queue.clear() #Clear existing queue
                [self.addrQueue.put(i) for i in[ip_prefix1 + '.' + ip_prefix2 + '.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]] #Rebuild IP Queue

            else:
                print("Please enter valid integers 0 < n < 256")
            configState['FREQUENCY'] = 'REPORT', report_freq
            configState['TYPE'] = 'DISCOVERY', disc_choice
            FileIO.write_Config(self, configState)  # Combine this with FileIO.write_Config?
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
        self.type = None
        self.oui = None


root = tk.Tk()
app = NetworkMonitor(root)
root.mainloop()