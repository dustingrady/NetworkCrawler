#Author: Dustin Grady
#Purpose: Module to support common scan functions
#Status: In development

import nmap
from netaddr import EUI, NotRegisteredError

'''Return index of a given IP address within record_list'''
def get_record_index(ip, record_list):
    for i, rec in enumerate(record_list):
        if rec.ip == ip:
            return i
    return 'No record found'


'''Collect OUI (vendor)'''
def retrieve_oui(record):
    mac = EUI(record.mac)
    try:
        org = mac.oui.registration().org
    except NotRegisteredError:
        org = None
    return org


'''Collect Operating System (uses best guess)'''
def retrieve_os(record):
    nm = nmap.PortScanner()
    try:
        nm.scan(record.ip, arguments='-O')
        if 'osmatch' in nm[record.ip]:
            os = nm[record.ip]['osmatch'][0]['name']
            conf = nm[record.ip]['osmatch'][0]['accuracy']
    except:
        os = 'None detected. Running as admin?'
        conf = ''
    return [os, conf]


'''Collect visible ports'''
def retrieve_port_status(record):
    nm = nmap.PortScanner()
    ports = []
    nm.scan(record.ip, '0-1023')
    try:
        for port in nm[record.ip]['tcp'].keys():
            ports.append([port, nm[record.ip]['tcp'][port]['state']])
    except KeyError:
        return None
    return ports
