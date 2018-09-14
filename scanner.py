#Author: Dustin Grady
#Purpose: Crawl through network and discover connected devices
#Status: In development

from getmac import get_mac_address
import utils
import fileio
import interface
import tkinter as tk
import warnings
import threading
import queue
import os

class NetworkMonitor:
    warnings.filterwarnings("ignore")  # Ignore warning from get-mac lib

    def __init__(self):
        self.run_scan = True
        self.MAX_THREADS = 128
        self.configuration = fileio.read_config()
        self.addr_queue = queue.Queue()
        self.record_list = []
        self.results_list = tk.Listbox

    '''Using 16-bit IPv4 scheme (after a successful ping, arp -a command can be run)'''
    def scan_network(self, scan_type):
        while not self.addr_queue.empty() and self.run_scan:
            addr = self.addr_queue.get()
            interface.GUI.build_status(self, 'Scanning ' + addr)
            try:
                if scan_type == 'ARP':
                    arp_output = []  # Move this somewhere outside of loop(?)
                    response = os.system('ping -n 1 ' + addr + ' > nul')
                    mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
                    if response == 0 and mac:
                        print('Ping successful, running ARP command..', flush=True)
                        interface.GUI.build_status(self, 'Ping successful, running ARP command..')
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
                                      '\tOS: ', record.op_sys,
                                      flush=True)
                                self.record_list.append(record)
                                interface.GUI.build_result(self)
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
                              '\tOS: ', record.op_sys,
                              flush=True)
                        self.record_list.append(record)
                        interface.GUI.build_result(self)
                        fileio.build_report(self.record_list)
                    else:
                        pass
            except:
                print('Error during scan')


    '''Create multiple threads to accelerate pinging'''
    #Disable Start Scan button after start
    def start_scan(self):
        interface.GUI.results_window(self)
        self.configuration = fileio.read_config()
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
        self.addr_queue.queue.clear()
        del self.record_list[:]
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
        self.op_sys = 'Unknown'
        self.op_acc = '0'
        self.ports = []
