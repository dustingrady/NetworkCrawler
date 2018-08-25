#Author: Dustin Grady
#Purpose: Provide access to commonly used methods
#Status: In development

import csv
import nmap
import configparser
from netaddr import *

'''File I/O'''
class FileIO():
    def __init__(self):
        pass

    def read_Config(self):
        configDict = {}
        config = configparser.ConfigParser()
        config.read('config.ini')
        configDict['IP_PREFIX'] = config['IP_PREFIX']['OCTET_ONE'], config['IP_PREFIX']['OCTET_TWO']
        configDict['REPORT'] = config['REPORT']['FREQUENCY']
        configDict['DISCOVERY'] = config['DISCOVERY']['TYPE']
        configDict['THREADS'] = int(config['THREADS']['COUNT'])
        return configDict

    def write_Config(self, configState):
        config = configparser.ConfigParser()
        config.read('config.ini')
        for key in configState:
            config.set(str(configState[key][0]), str(key), str(configState[key][1]))

        with open('config.ini', 'w+') as configFile:
            config.write(configFile)

    def build_Report(self, recordList):
        with open('records.tsv', 'w') as output:
            writer = csv.writer(output, delimiter='\t')
            writer.writerow(["IP", "MAC", "TYPE", "OUI"]) #Headers
            for record in recordList:
                #print('Record: ', record.ip, record.mac, record.type, record.oui)
                writer.writerow([record.ip, record.mac, record.type, record.oui])

'''Attempt to retrieve information based on MAC address'''
class GetInfo():
    def retrieve_OUI(self, addr):
        mac = EUI(addr)
        try:
            org = mac.oui.registration().org
        except NotRegisteredError:
            org = None
        return org

    '''Gather information about host Operating System'''
    def retrieve_OS(self, addr):
        nm = nmap.PortScanner()
        os = None
        try:
            nm.scan(addr, arguments='-O')
            if 'osmatch' in nm[addr]:
                os = nm[addr]['osmatch'][0]['osclass'][0]['osfamily']
        except KeyError:
            os = None
        return os


'''Send reports out'''
class GenerateEmail():
    def __init__(self):
        pass

    def send_Email(self):
        pass