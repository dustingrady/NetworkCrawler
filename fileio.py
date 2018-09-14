#Author: Dustin Grady
#Purpose: Module to provide easy file i/o operations
#Status: In development


import sys
import csv
import configparser


'''File I/O'''
def read_config():
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


'''Update config.ini'''
def save_config(ip_prefix1, ip_prefix2, report_freq, disc_choice, thread_count):  # Pass a dict instead?
    configState = {}
    if 0 < int(ip_prefix1) < 256 and 0 < int(ip_prefix2) < 256:
        configState['OCTET_ONE'] = 'IP_PREFIX', ip_prefix1
        configState['OCTET_TWO'] = 'IP_PREFIX', ip_prefix2
    else:
        print("Please enter valid integers 0 < n < 256")

    configState['FREQUENCY'] = 'REPORT', report_freq
    configState['TYPE'] = 'DISCOVERY', disc_choice
    configState['COUNT'] = 'THREADS', thread_count
    write_config(configState)


def write_config(configState):
    config = configparser.ConfigParser()
    config.read('config.ini')
    for key in configState:
        config.set(str(configState[key][0]), str(key), str(configState[key][1]))
    with open('config.ini', 'w+') as configFile:
        config.write(configFile)


def build_report(recordList):
    with open('records.tsv', 'w') as output:
        writer = csv.writer(output, delimiter='\t')
        writer.writerow(["IP", "MAC", "TYPE", "OUI"]) #Headers
        for record in recordList:
            writer.writerow([record.ip, record.mac, record.type, record.oui])