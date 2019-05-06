#Author: Dustin Grady
#Purpose: Crawl through network and discover connected devices
#Status: In development

from subprocess import Popen, PIPE
from getmac import get_mac_address
import tkinter as tk
import subprocess
import threading
import warnings
import fileio
import utils
import queue
import os


class NetworkMonitor:
    warnings.filterwarnings("ignore")  # Ignore warning from get-mac lib

    def __init__(self, gui):
        self.run_scan = True
        self.configuration = fileio.read_config()
        self.gui = gui
        self.addr_queue = queue.Queue()
        self.record_list = []
        self.results_list = tk.Listbox

    '''Using 16-bit IPv4 scheme (after a successful ping, arp -a command can be run)'''
    def scan_network(self, scan_type):
        while not self.addr_queue.empty() and self.run_scan:
            addr = self.addr_queue.get()
            self.gui.update_status('Scanning ' + addr, self.addr_queue.qsize())
            #try:
            mac = get_mac_address(ip=addr)  # Throws runtime warning after first set of threads completes..?
            process = subprocess.Popen('ping -c 1 ' + addr, shell=True)
            (output, err) = process.communicate()
            exit_code = process.wait()

            if scan_type == 'ARP':
                if exit_code == 0 and mac and "TTL expired in transit" not in str(output):
                    self.run_scan = False  # Stop scan after successful ping
                    print('Ping successful, running ARP command..', flush=True)
                    self.gui.scan_progress_bar['value'] = 100
                    self.gui.update_status('Ping successful, running ARP command..')
                    arp = os.popen('arp -a').read()
                    for i, val in enumerate(arp.split('\n')):
                        if len(val.split()) == 3:
                            record = Record()
                            record.ip = val.split()[0]
                            record.mac = val.split()[1]
                            record.type = val.split()[2]
                            record.oui = utils.retrieve_oui(record)
                            '''
                            print('IP: ', record.ip,
                                  '\tMAC: ', record.mac,
                                  '\tType: ', record.type,
                                  '\tVendor: ', record.oui,
                                  '\tOS: ', record.op_sys,
                                  flush=True)
                            '''
                            self.record_list.append(record)
                            self.gui.build_result()
                    fileio.build_report(self.record_list)

            if scan_type == 'Ping':
                if exit_code == 0 and mac and "TTL expired in transit" not in str(output):
                    record = Record()
                    record.ip = addr
                    record.mac = mac
                    record.type = None  # Unavailable for this method
                    record.oui = utils.retrieve_oui(record)
                    '''
                    print('IP: ', record.ip,
                          '\tMAC: ', record.mac,
                          '\tVendor: ', record.oui,
                          '\tOS: ', record.op_sys,
                          flush=True)
                    '''
                    self.record_list.append(record)
                    self.gui.build_result()
                    fileio.build_report(self.record_list)
            #except:
            #    print('Error during scan')

    '''Create multiple threads to accelerate pinging'''
    def start_scan(self):
        self.record_list[:] = []
        self.gui.clear_result_window()
        [self.addr_queue.put(i) for i in [self.configuration['IP_PREFIX'][0] + '.' + self.configuration['IP_PREFIX'][1] + '.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]
        scan_type = self.configuration['DISCOVERY']
        print('Discovering devices via brute force ping' if scan_type == 'Ping' else 'Displaying Address Resolution Protocol (ARP) Table', flush=True)
        self.run_scan = True
        threads = {}
        for i in range(0, self.configuration['THREADS']):
            threads['thread' + str(i)] = threading.Thread(target=lambda: NetworkMonitor.scan_network(self, scan_type))  # Create thread
            threads['thread' + str(i)].start()  # Start thread

    '''Cancel current scan'''
    def stop_scan(self):
        print('Stopping scan..', flush=True)
        self.gui.update_status('Scan stopped..')
        self.run_scan = False
        self.addr_queue.queue.clear()


class Record:
    def __init__(self):
        self.ip = '0.0.0.0'
        self.mac = '00:00:00:00:00:00'
        self.type = 'Unknown'
        self.oui = 'Unknown'
        self.op_sys = 'Unknown'
        self.op_acc = '0'
        self.ports = []
        self.details_processed = False
