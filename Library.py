#Author: Dustin Grady
#Purpose: Provide access to commonly used methods
#Status: In development

import csv

'''File I/O'''
class FileOutput():
    def __init__(self):
        pass

    def build_Report(self, recordList):
        with open('records.tsv', 'w') as output:
            writer = csv.writer(output, delimiter='\t')
            for record in recordList:
                print('Record: ', record.ip, record.mac)
                writer.writerow([record.ip, record.mac])

'''Send reports out'''
class GenerateEmail():
    def __init__(self):
        pass

    def send_Email(self):
        pass