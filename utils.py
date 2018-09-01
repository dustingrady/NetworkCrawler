#Author: Dustin Grady
#Purpose: Provide access to commonly used methods
#Status: In development

import csv
import sys
import nmap
import configparser
from netaddr import EUI, NotRegisteredError

'''File I/O'''
class FileIO:

    def read_config(self):
        configDict = {}
        config = configparser.ConfigParser()
        try:
            config.read('config.ini')
            configDict['IP_PREFIX'] = config['IP_PREFIX']['OCTET_ONE'], config['IP_PREFIX']['OCTET_TWO']
            configDict['REPORT'] = config['REPORT']['FREQUENCY']
            configDict['DISCOVERY'] = config['DISCOVERY']['TYPE']
            configDict['THREADS'] = int(config['THREADS']['COUNT'])
        except:
            print("Error reading config.")
            sys.exit(1)

        return configDict

    '''Update config.ini (perform checks on values here?)'''
    def save_config(self, ip_prefix1, ip_prefix2, report_freq, disc_choice, thread_count):
        configState = {}
        if 0 < int(ip_prefix1) < 256 and 0 < int(ip_prefix2) < 256:
            configState['OCTET_ONE'] = 'IP_PREFIX', ip_prefix1
            configState['OCTET_TWO'] = 'IP_PREFIX', ip_prefix2
            #self.addrQueue.queue.clear()  # Clear existing queue
            #[self.addrQueue.put(i) for i in
            # [ip_prefix1 + '.' + ip_prefix2 + '.' + str(x) + '.' + str(y) for x in range(0, 256) for y in
            #  range(0, 256)]]  # Rebuild IP Queue

        else:
            print("Please enter valid integers 0 < n < 256")
        configState['FREQUENCY'] = 'REPORT', report_freq
        configState['TYPE'] = 'DISCOVERY', disc_choice
        configState['COUNT'] = 'THREADS', thread_count
        FileIO.write_config(self, configState)
        config = FileIO.read_config(self)  # Read back changes

    def write_config(self, configState):
        config = configparser.ConfigParser()
        config.read('config.ini')
        for key in configState:
            config.set(str(configState[key][0]), str(key), str(configState[key][1]))
        with open('config.ini', 'w+') as configFile:
            config.write(configFile)

    def build_report(self, recordList):
        with open('records.tsv', 'w') as output:
            writer = csv.writer(output, delimiter='\t')
            writer.writerow(["IP", "MAC", "TYPE", "OUI"]) #Headers
            for record in recordList:
                writer.writerow([record.ip, record.mac, record.type, record.oui])

'''Attempt to retrieve information based on MAC address'''
class GetInfo:
    def retrieve_oui(self, addr):
        mac = EUI(addr)
        try:
            org = mac.oui.registration().org
        except NotRegisteredError:
            org = None
        return org

    '''Gather information about host Operating System'''
    def retrieve_os(self, addr):
        nm = nmap.PortScanner()
        os = None
        try:
            nm.scan(addr, arguments='-O')
            if 'osmatch' in nm[addr]:
                os = nm[addr]['osmatch'][0]['osclass'][0]['osfamily']
        except KeyError:
            os = None
        return os

    '''Scan a range of ports and report their status (open/closed)'''
    def retrieve_port_status(self, addr):
        nm = nmap.PortScanner()
        ports = []
        nm.scan(addr, '0-1023')
        try:
            for port in nm[addr]['tcp'].keys():
                ports.append([port, nm[addr]['tcp'][port]['state']])
        except KeyError:
            return None
        return ports

'''Send reports out'''
class GenerateEmail:

    def send_Email(self):
        pass