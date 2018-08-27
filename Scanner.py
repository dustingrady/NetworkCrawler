#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user.
#Status: In development
#To do:
    #-Change output formatting to be line by line
    #-Remove from recordsList if device not found again
#Bugs:

from getmac import get_mac_address
from utils import FileIO, GetInfo
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
        self.resultsList = tk.Listbox
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

        '''Start/Stop buttons'''
        button_frame = tk.Frame(self.master)
        start_button = tk.Button(button_frame, text="Start", command=lambda: self.start_Scan(self.config['THREADS'])).pack(side='left')
        stop_button = tk.Button(button_frame, text="Stop", command=lambda: self.stop_Scan()).pack(side='left')
        button_frame.grid(row=0, column=1, padx='120', pady='75')

    '''Program description window'''
    def about_Window(self):
        about_win = tk.Toplevel()
        about_win.wm_title("About")
        about_label = tk.Label(about_win, text="NetMon 2018\n A multithreaded pinging tool designed to monitor for\n new connections to a network and generate basic reports.")
        about_label.grid(row=0, column=0)
        about_win.geometry('325x70')
        about_win.transient(self.master)  # Only one window in taskbar
        about_win.grab_set() #Modal
        about_win.resizable(False, False)


    '''Provides r/w access to config.ini'''
    def config_Window(self):
        config_win = tk.Toplevel()
        config_frame = tk.Frame(config_win)
        config_win.wm_title("Configuration")
        config_label = tk.Label(config_frame, text="<<<Configuration>>>").pack(side='top')
        config_frame.grid(row=0, column=0)
        config_win.resizable(False, False)

        '''IP Prefix Selection'''
        ip_frame = tk.Frame(config_win)
        ip_desc_label = tk.Label(ip_frame, text="Network prefix ").pack(side='left')
        prefix1_val = tk.StringVar()
        prefix2_val = tk.StringVar()

        prefix1_val.set(self.config['IP_PREFIX'][0])  # Set values from ini file
        prefix2_val.set(self.config['IP_PREFIX'][1])
        ip_prefix_form1 = tk.Entry(ip_frame, textvariable=prefix1_val, width=5).pack(side='left')
        dot = tk.Label(ip_frame, text=" . ").pack(side='left')
        ip_prefix_form2 = tk.Entry(ip_frame, textvariable=prefix2_val, width=5).pack(side='left')
        ip_suffix = tk.Label(ip_frame, text=" . X . X").pack(side='left')
        ip_frame.grid(row=1, column=0, sticky='w')

        '''Reports'''
        report_frame = tk.Frame(config_win)
        report_label = tk.Label(report_frame, text="Report frequency ").pack(side='left')
        report_freq = ['Live', '1 hour', '6 hours', '12 hours', '24 hours', 'Never']
        freq_choice = tk.StringVar(root)
        freq_choice.set(self.config['REPORT'])
        freq_menu = tk.OptionMenu(report_frame, freq_choice, *report_freq).pack(side='left')
        report_frame.grid(row=2, column=0, padx='5', sticky='w')

        '''Discovery Type'''
        discovery_frame = tk.Frame(config_win)
        report_label = tk.Label(discovery_frame, text="Discovery method ").pack(side='left')
        disc_choice = tk.StringVar(root)
        disc_choice.set(self.config['DISCOVERY'])
        disc_menu = tk.OptionMenu(discovery_frame, disc_choice, *['ARP', 'Ping']).pack(side='left')
        discovery_frame.grid(row=3, column=0, sticky='w')

        '''Thread Slider'''
        thread_frame = tk.Frame(config_win)
        thread_label = tk.Label(thread_frame, text="Threads").pack(side='left')
        thread_slider = tk.Scale(thread_frame, from_=8, to=self.MAX_THREADS, resolution=8, length=150, orient='horizontal')
        thread_slider.set(self.config['THREADS'])
        thread_slider.pack(side='left')
        thread_frame.grid(row=5, column=0, sticky='w')

        '''Save Button'''
        save_button = tk.Button(config_win, text="Save", command=lambda: (
        self.save_Config(prefix1_val.get(), prefix2_val.get(), freq_choice.get(), disc_choice.get(), thread_slider.get()), config_win.destroy()))  # Could probably be cleaned up
        save_button.grid(row=6, column=0)

        config_win.transient(self.master)  # Only one window in taskbar
        config_win.grab_set()  # Modal


    '''Display list of scan results'''
    def results_Window(self):
        results_win = tk.Toplevel()
        self.results_frame = tk.Frame(results_win)
        self.results_frame.pack(side='top')

        self.header_label = tk.Label(self.results_frame, text="IP\t\tMAC\tVENDOR", font=('Helvetica', 11))  # Results header
        self.header_label.pack(side='top', anchor='w')

        self.results_scroll = tk.Scrollbar(self.results_frame, orient='vertical')
        self.results_scroll.pack(side='right', fill='y')

        self.results_canvas = tk.Canvas(self.results_frame, bd=0, width=500) #, width=500
        self.results_canvas.pack(fill='both', side='left')

        self.viewArea = tk.Frame(self.results_canvas)
        self.viewArea.pack(side='top', fill='both')

        self.results_canvas.config(yscrollcommand=self.results_scroll.set)
        self.results_scroll.config(command=self.results_canvas.yview)
        self.results_canvas.create_window((0, 0), window=self.viewArea, anchor='nw')

        self.viewArea.bind("<Configure>", lambda x: self.results_canvas.config(scrollregion=self.results_canvas.bbox("all")))  # Resize scroll region when widget size changes


    '''Updates results_Window'''
    def build_Result(self):
        for i, rec in enumerate(self.recordList):
            rec_label = tk.Label(self.viewArea, text=str(rec.ip) + '\t' + str(rec.mac) + '\t' + str(rec.oui), background='gray80' if i % 2 is 0 else 'gray60') #, background='gray80' if i % 2 is 0 else 'gray60'
            details_button = tk.Button(self.viewArea, text="Details", command=lambda i=i: self.details_Window(self.recordList[i]))
            rec_label.grid(row=i, column=0, sticky='ew')
            details_button.grid(row=i, column=1, sticky='ew')


    '''Show more details of a device'''
    def details_Window(self, record):
        print(record.ip)
        #Look up OS info, open ports, etc


    '''Using 16-bit IPv4 scheme (after a successful ping, arp -a command can be run)'''
    def scan_Network(self, scanType):
        while not self.addrQueue.empty() and self.runScan:
            addr = self.addrQueue.get()
            #try:
            if scanType == 'ARP':
                arpOutput = []  # Move this somewhere outside of loop(?)
                response = os.system('ping -n 1 ' + addr + ' > nul')
                mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                if response == 0 and mac:
                    print('Ping successful, running ARP command..', flush=True)
                    self.runScan = False  # Stop scan after successful ping
                    arp = os.popen('arp -a').read()
                    #op = GetInfo.retrieve_OS(self, addr)  # Takes too long
                    for i, val in enumerate(arp.split('\n')):
                        arpOutput.append(val.split())
                        if len(arpOutput[i]) == 3:
                            oui = GetInfo.retrieve_OUI(self, arpOutput[i][1])
                            record = Record()
                            record.ip = arpOutput[i][0]
                            record.mac = arpOutput[i][1]
                            record.type = arpOutput[i][2]
                            record.oui = oui
                            #record.op = op
                            print('IP: ', record.ip,
                                  '\tMAC: ', record.mac,
                                  '\type: ', record.type,
                                  '\tVendor: ', record.oui,
                                  '\tOS: ', record.op,
                                  flush=True)
                            self.recordList.append(record)
                            self.build_Result()
                    FileIO.build_Report(self, self.recordList)
                else:
                    pass

            if scanType == 'Ping':
                response = os.system('ping -n 1 ' + addr + ' > nul')
                mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                #op = GetInfo.retrieve_OS(self, addr)  # Takes too long
                if response == 0 and mac:
                    oui = GetInfo.retrieve_OUI(self, mac)
                    record = Record()
                    record.ip = addr
                    record.mac = mac
                    record.type = None  # Unavailable for this method
                    record.oui = oui
                    #record.op = op
                    print('IP: ', record.ip,
                          '\tMAC: ', record.mac,
                          '\tVendor: ', record.oui,
                          '\tOS: ', record.op,
                          flush=True)
                    self.recordList.append(record)
                    self.build_Result()
                    FileIO.build_Report(self, self.recordList)
                else:
                    pass
            #except:
            #    print('Error during scan')
            self.addrQueue.put(addr)


    '''Create multiple threads to accelerate pinging'''
    def start_Scan(self, threadCount):
        self.results_Window()  # Bring up results window
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
    def save_Config(self, ip_prefix1, ip_prefix2, report_freq, disc_choice, thread_count):
        configState = {}
        try:
            if 0 < int(ip_prefix1) < 256 and 0 < int(ip_prefix2) < 256:
                configState['OCTET_ONE'] = 'IP_PREFIX', ip_prefix1
                configState['OCTET_TWO'] = 'IP_PREFIX', ip_prefix2
                self.addrQueue.queue.clear()  # Clear existing queue
                [self.addrQueue.put(i) for i in[ip_prefix1 + '.' + ip_prefix2 + '.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]  # Rebuild IP Queue

            else:
                print("Please enter valid integers 0 < n < 256")
            configState['FREQUENCY'] = 'REPORT', report_freq
            configState['TYPE'] = 'DISCOVERY', disc_choice
            configState['COUNT'] = 'THREADS', thread_count
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
        self.type = 'Unknown'
        self.oui = 'Unknown'
        self.op = 'Unknown'


root = tk.Tk()
app = NetworkMonitor(root)
root.geometry('300x100')
root.resizable(False, False)
root.mainloop()
