#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user. Also an excuse to play with threading.
#Status: In development/ Untested


from tkinter import Tk, Label, Button
import threading
import os

class NetworkMonitor:
    def __init__(self, master):
        self.master = master
        master.title('Network Monitor v0.1')

        self.greet_button = Button(master, text="Scan", command=self.scan_Network)
        self.greet_button.grid(row=0, column=1)

        self.close_button = Button(master, text="Close", command=master.quit)
        self.close_button.grid(row=1, column=1)

        self.THREAD_COUNT = 8
        self.threads = {}
        for i in range(0, self.THREAD_COUNT-1):
            self.threads['thread' + str(i)] = threading.Thread(target=lambda: self.scan_Network) #Create thread
            self.threads['thread' + str(i)].start() #Start thread

    '''Using 16-bit IPv4 schema'''
    def scan_Network(self):
        for x in range(0, 256):
            for y in range(0, 256):
                addr = '192.168.'+str(x)+'.'+str(y)
                print("Threads: " + str(threading.active_count())) #Testing
                #addr = '192.168.1.232' #Testing
                response = os.system("ping -n 1 " + addr)
                if response == 0:
                    print(addr, 'is up!')
                else:
                    print(addr, 'is down!')

root = Tk()
app = NetworkMonitor(root)
root.geometry('400x400')
root.mainloop()