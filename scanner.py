#Author: Dustin Grady
#Purpose: Crawl through network and discover connected devices
#Status: In development

from getmac import get_mac_address
import utils, fileio
import tkinter as tk
from tkinter.ttk import Progressbar
import warnings
import threading
import queue
import os


class GUI:
    def __init__(self, master):
        self.master = master
        self.master.title('v0.1')
        self.build_gui()
        self.configuration = fileio.read_config()
        self.net_mon = NetworkMonitor()

    def build_gui(self):
        ''''File menu'''''
        menubar = tk.Menu(root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Configure", command=self.config_window)
        file_menu.add_command(label="About", command=self.about_window)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        root.config(menu=menubar)

        '''Logo'''
        logo_frame = tk.Frame(self.master)
        photo = tk.PhotoImage(file="./source/logo.png")
        logo_label = tk.Label(self.master, image=photo)
        logo_label.image = photo
        logo_label.grid(row=0, column=1, padx=50, pady=20)

        '''Start/Stop buttons'''
        button_frame = tk.Frame(self.master)
        start_button = tk.Button(button_frame, text="Start", command=lambda: self.net_mon.start_scan()).pack(side='left')
        stop_button = tk.Button(button_frame, text="Stop", command=lambda: self.net_mon.stop_scan()).pack(side='left')
        button_frame.grid(row=1, column=1, padx=50, pady=20)

    '''Program description window'''
    def about_window(self):
        about_win = tk.Toplevel()
        about_win.wm_title("About")
        about_label = tk.Label(about_win,
                               text="Network Discovery Tool 2018\n A multithreaded network discovery tool designed to discover\n devices within a network and provide reports on the information gathered")
        about_label.grid(row=0, column=0, padx=15, pady=15)
        #about_win.geometry('325x70')
        about_win.grab_set()  # Modal
        about_win.resizable(False, False)

    '''Provides r/w access to config.ini'''
    def config_window(self):
        self.configuration = fileio.read_config()

        config_win = tk.Toplevel()
        config_frame = tk.Frame(config_win)
        config_win.wm_title("Configuration")
        config_label = tk.Label(config_frame, text="Configuration", font=('Helvetica', 10, 'bold')).pack(side='top')
        config_frame.grid(row=0, column=0)
        config_win.resizable(False, False)

        '''IP Prefix Selection'''
        ip_frame = tk.Frame(config_win)
        ip_desc_label = tk.Label(ip_frame, text="Network prefix ").pack(side='left')
        prefix1_val = tk.StringVar()
        prefix2_val = tk.StringVar()

        prefix1_val.set(self.configuration['IP_PREFIX'][0])
        prefix2_val.set(self.configuration['IP_PREFIX'][1])
        ip_prefix_form1 = tk.Entry(ip_frame, textvariable=prefix1_val, width=5).pack(side='left')
        dot = tk.Label(ip_frame, text=" . ").pack(side='left')
        ip_prefix_form2 = tk.Entry(ip_frame, textvariable=prefix2_val, width=5).pack(side='left')
        ip_suffix = tk.Label(ip_frame, text=" . X . X").pack(side='left')
        ip_frame.grid(row=1, column=0, pady=5, sticky='w')

        '''Reports'''
        report_frame = tk.Frame(config_win)
        report_label = tk.Label(report_frame, text="Report frequency ").pack(side='left')
        report_freq = ['Live', '1 hour', '6 hours', '12 hours', '24 hours', 'Never']
        freq_choice = tk.StringVar(root)
        freq_choice.set(self.configuration['REPORT'])
        freq_menu = tk.OptionMenu(report_frame, freq_choice, *report_freq).pack(side='left')
        report_frame.grid(row=2, column=0, pady=5, sticky='w')

        '''Discovery Type'''
        discovery_frame = tk.Frame(config_win)
        report_label = tk.Label(discovery_frame, text="Discovery method ").pack(side='left')
        disc_choice = tk.StringVar(root)
        disc_choice.set(self.configuration['DISCOVERY'])
        disc_menu = tk.OptionMenu(discovery_frame, disc_choice, *['ARP', 'Ping']).pack(side='left')
        discovery_frame.grid(row=3, column=0, pady=5, sticky='w')

        '''Thread Slider'''
        thread_frame = tk.Frame(config_win)
        thread_label = tk.Label(thread_frame, text="Threads").pack(side='left')
        thread_slider = tk.Scale(thread_frame, from_=8, to=self.net_mon.MAX_THREADS, resolution=8, length=150,
                                 orient='horizontal')
        thread_slider.set(self.configuration['THREADS'])
        thread_slider.pack(side='left')
        thread_frame.grid(row=5, column=0, pady=5, sticky='w')

        '''Save Button'''
        save_button = tk.Button(config_win, text="Save", command=lambda: (fileio.save_config(prefix1_val.get(), prefix2_val.get(), freq_choice.get(), disc_choice.get(), thread_slider.get()), config_win.destroy()))  # Could probably be cleaned up (pass dict?)
        save_button.grid(row=6, column=0, pady=5)

        config_win.grab_set()  # Modal

    '''Display list of scan results'''
    def results_window(self):
        results_win = tk.Toplevel()
        results_win.title('Results')

        results_frame = tk.Frame(results_win)
        results_frame.pack(side='top')

        results_scroll = tk.Scrollbar(results_frame, orient='vertical')
        results_scroll.pack(side='right', fill='y')

        results_canvas = tk.Canvas(results_frame, bd=0, width=500)
        results_canvas.pack(fill='both', side='left')

        self.viewArea = tk.Frame(results_canvas)
        self.viewArea.pack(side='top', fill='both')

        results_canvas.config(yscrollcommand=results_scroll.set)
        results_scroll.config(command=results_canvas.yview)
        results_canvas.create_window((0, 0), window=self.viewArea, anchor='nw')

        self.viewArea.bind("<Configure>", lambda x: results_canvas.config(
            scrollregion=results_canvas.bbox("all")))  # Resize scroll region when widget size changes
        #results_win.grab_set()  # Modal

        results_win.resizable(False, False)

    '''Updates results_window'''
    def build_result(self):
        ip_header_label = tk.Label(self.viewArea, text="IP", font=('Helvetica', 12, 'bold'))
        ip_header_label.grid(row=0, column=0)

        mac_header_label = tk.Label(self.viewArea, text="MAC", font=('Helvetica', 12, 'bold'))
        mac_header_label.grid(row=0, column=1)

        vendor_header_label = tk.Label(self.viewArea, text="Vendor", font=('Helvetica', 12, 'bold'))
        vendor_header_label.grid(row=0, column=2)

        for i, rec in enumerate(self.record_list):
            ip_label = tk.Label(self.viewArea, text=str(rec.ip), background='gray80' if i % 2 is 0 else 'gray60')
            mac_label = tk.Label(self.viewArea, text=str(rec.mac), background='gray80' if i % 2 is 0 else 'gray60')
            oui_label = tk.Label(self.viewArea, text=str(rec.oui), background='gray80' if i % 2 is 0 else 'gray60')
            details_button = tk.Button(self.viewArea, text="Details", command=lambda i=i: GUI.details_window(self, self.record_list[i]))

            ip_label.grid(row=i+1, column=0, sticky='ew')
            mac_label.grid(row=i+1, column=1, sticky='ew')
            oui_label.grid(row=i+1, column=2, sticky='ew')
            details_button.grid(row=i+1, column=3, sticky='ew')

    '''Show more details of a device'''
    def details_window(self, record):
        details_win = tk.Toplevel()
        details_win.title('Details')

        self.details_frame = tk.Frame(details_win)
        self.details_frame.pack(side='top')

        self.progress_label = tk.Label(self.details_frame, text="Gathering information..")
        self.progress_label.grid(row=0, column=0, columnspan=2)

        self.progress_bar = Progressbar(self.details_frame, orient='horizontal', length=100, mode='determinate')
        self.progress_bar.grid(row=1, column=0, padx=30, columnspan=2, sticky='ew')

        self.ip_label = tk.Label(self.details_frame, text="IP Address:")
        self.ip_result_label = tk.Label(self.details_frame, text="Loading..")
        self.ip_label.grid(row=2, column=0, padx=10, sticky='w')
        self.ip_result_label.grid(row=2, padx=10, column=1, sticky='w')

        self.mac_label = tk.Label(self.details_frame, text="MAC Address:")
        self.mac_result_label = tk.Label(self.details_frame, text="Loading..")
        self.mac_label.grid(row=3, column=0, padx=10, sticky='w')
        self.mac_result_label.grid(row=3, padx=10, column=1, sticky='w')

        self.oui_label = tk.Label(self.details_frame, text="Vendor:")
        self.oui_result_label = tk.Label(self.details_frame, text="Loading..")
        self.oui_label.grid(row=4, column=0, padx=10, sticky='w')
        self.oui_result_label.grid(row=4, padx=10, column=1, sticky='w')

        self.os_label = tk.Label(self.details_frame, text="OS/ Accuracy:")
        self.os_result_label = tk.Label(self.details_frame, text="Loading..")
        self.os_label.grid(row=5, column=0, padx=10, sticky='w')
        self.os_result_label.grid(row=5, padx=10, column=1, sticky='w')

        self.port_label = tk.Label(self.details_frame, text="Port Status:")
        self.port_placeholder_label = tk.Label(self.details_frame, text="Loading..")
        self.port_label.grid(row=6, column=0, padx=10, sticky='w')
        self.port_placeholder_label.grid(row=6, padx=10, column=1, sticky='w')

        self.details_thread = threading.Thread(target=lambda: GUI.build_details(self, record))  # Start thread to get results
        self.details_thread.start()

        details_win.grab_set()  # Modal
        details_win.resizable(False, False)

    def build_details(self, record):
        self.ip_result_label.config(text=str(record.ip))
        self.progress_bar['value'] = 10

        self.mac_result_label.config(text=str(record.mac))
        self.progress_bar['value'] = 20

        self.oui_result_label.config(text=str(record.oui))
        self.progress_bar['value'] = 30

        x, y = utils.retrieve_os(record)
        self.os_result_label.config(text=x + '/ ' + y + '%')
        self.progress_bar['value'] = 70

        try:
            for i, port in enumerate(utils.retrieve_port_status(record)):
                self.port_placeholder_label.config(text="")
                self.port_result_label = tk.Label(self.details_frame)
                self.port_result_label.config(text=port)
                self.port_result_label.grid(row=i+6, column=1, sticky='w')
        except TypeError:
            self.port_placeholder_label.config(text="None detected")
        self.progress_bar['value'] = 100
        self.progress_label.config(text="Scan complete")


class NetworkMonitor:
    warnings.filterwarnings("ignore")  # Ignore warning from get-mac lib

    def __init__(self):
        self.run_scan = True
        self.MAX_THREADS = 128
        self.addr_queue = queue.Queue()
        self.configuration = fileio.read_config()
        self.record_list = []
        self.resultsList = tk.Listbox


    '''Using 16-bit IPv4 scheme (after a successful ping, arp -a command can be run)'''
    def scan_network(self, scan_type):
        while not self.addr_queue.empty() and self.run_scan:
            addr = self.addr_queue.get()
            try:
                if scan_type == 'ARP':
                    arp_output = []  # Move this somewhere outside of loop(?)
                    response = os.system('ping -n 1 ' + addr + ' > nul')
                    mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                    if response == 0 and mac:
                        print('Ping successful, running ARP command..', flush=True)
                        self.run_scan = False  # Stop scan after successful ping
                        arp = os.popen('arp -a').read()
                        for i, val in enumerate(arp.split('\n')):
                            arp_output.append(val.split())
                            if len(arp_output[i]) == 3:
                                record = Record()
                                record.ip = arp_output[i][0]
                                record.mac = arp_output[i][1]
                                record.type = arp_output[i][2]
                                record.oui = utils.retrieve_oui(record)

                                print('IP: ', record.ip,
                                      '\tMAC: ', record.mac,
                                      '\type: ', record.type,
                                      '\tVendor: ', record.oui,
                                      '\tOS: ', record.op,
                                      flush=True)
                                self.record_list.append(record)
                                GUI.build_result(self)
                        fileio.build_report(self.record_list)
                    else:
                        pass

                if scan_type == 'Ping':
                    response = os.system('ping -n 1 ' + addr + ' > nul')
                    mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                    if response == 0 and mac:
                        record = Record()
                        record.ip = addr
                        record.mac = mac
                        record.type = None  # Unavailable for this method
                        record.oui = utils.retrieve_oui(record)
                        print('IP: ', record.ip,
                              '\tMAC: ', record.mac,
                              '\tVendor: ', record.oui,
                              '\tOS: ', record.op,
                              flush=True)
                        self.record_list.append(record)
                        GUI.build_result(self)
                        fileio.build_report(self.record_list)
                    else:
                        pass
            except:
                print('Error during scan')
            self.addr_queue.put(addr)

    '''Create multiple threads to accelerate pinging'''
    def start_scan(self):
        GUI.results_window(self)
        self.configuration = fileio.read_config()
        self.addr_queue.queue.clear()
        [self.addr_queue.put(i) for i in [self.configuration['IP_PREFIX'][0] + '.' + self.configuration['IP_PREFIX'][1] + '.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]
        scan_type = self.configuration['DISCOVERY']
        print('Discovering devices via brute force ping' if scan_type == 'Ping' else 'Displaying Address Resolution Protocol (ARP) Table', flush=True)
        self.run_scan = True
        self.threads = {}
        for i in range(0, self.configuration['THREADS']):
            self.threads['thread' + str(i)] = threading.Thread(target=lambda: NetworkMonitor.scan_network(self, scan_type))  # Create thread
            self.threads['thread' + str(i)].start()  # Start thread

    '''Cancel current scan'''
    def stop_scan(self):
        print('Stopping scan..', flush=True)
        self.run_scan = False
        #self.master.quit()

    '''Send email to user'''
    def alert_user(self):
        print("Emailing user..")


'''Record object'''
class Record:
    def __init__(self):
        self.ip = '0.0.0.0'
        self.mac = '00:00:00:00:00:00'
        self.type = 'Unknown'
        self.oui = 'Unknown'
        self.op = 'Unknown'
        self.ports = []

root = tk.Tk()
app = GUI(root)
#root.geometry('175x175')
root.resizable(False, False)
root.mainloop()
