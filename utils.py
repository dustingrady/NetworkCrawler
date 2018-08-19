#Author: Dustin Grady
#Purpose: Provide access to commonly used methods
#Status: In development

import csv
import configparser

'''File I/O'''
class FileIO():
    def __init__(self):
        pass

    def read_Config(self):
        configDict = {}
        config = configparser.ConfigParser()
        config.read('config.ini')
        configDict['IP_PREFIX'] = config['IP_PREFIX']['OCTET_ONE'], config['IP_PREFIX']['OCTET_TWO']
        configDict['report'] = config['REPORT']['FREQUENCY']
        return configDict

    def write_Config(self, configState):
        config = configparser.ConfigParser()
        config.read('config.ini')
        for key in configState:
            #print('Val1: ', str(configState[key][0]), flush=True)
            #print('Val2: ', str(key), flush=True)
            #print('Val3: ', str(configState[key][1]), flush=True)

            config.set(str(configState[key][0]), str(key), str(configState[key][1])) #config.set(section, key, value)

        with open('config.ini', 'w+') as configFile:
            config.write(configFile)

    def build_Report(self, recordList):
        with open('records.tsv', 'w') as output:
            writer = csv.writer(output, delimiter='\t')
            writer.writerow(["IP", "MAC"]) #Headers
            for record in recordList:
                print('Record: ', record.ip, record.mac)
                writer.writerow([record.ip, record.mac])

'''Send reports out'''
class GenerateEmail():
    def __init__(self):
        pass

    def send_Email(self):
        pass