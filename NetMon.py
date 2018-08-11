#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user. Also an excuse to play with threading.
#Status: In development/ Untested


from tkinter import Tk, Label, Button
import threading
import queue
import os

class NetworkMonitor:
    def __init__(self, master):
        self.master = master
        master.title('Network Monitor v0.1')

        self.THREAD_COUNT = 8

        self.addrQueue = queue.Queue()
        [self.addrQueue.put(i) for i in ['192.168.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]

        self.thread = threading.Thread(target=self.scan_Network)
        self.thread.daemon = True

        self.build_GUI()

        #self.threads = {}
        #for i in range(0, self.THREAD_COUNT):
        #    self.threads['thread' + str(i)] = threading.Thread(target=self.scan_Network) #Create thread
        #    self.threads['thread' + str(i)].start() #Start thread

    '''Draw GUI elements'''
    def build_GUI(self):
        #self.scan_button = Button(self.master, text="Scan", command=self.scan_Network)
        self.scan_button = Button(self.master, text="Scan", command=lambda: self.thread.start())

        self.scan_button.grid(row=0, column=1)

        self.close_button = Button(self.master, text="Close", command=self.master.quit)
        self.close_button.grid(row=1, column=1)

    '''Using 16-bit IPv4 schema'''
    def scan_Network(self):
        while not self.addrQueue.empty():
            addr = self.addrQueue.get()
            try:
                print('Address: ', addr)  #Testing
                print("Threads: " + str(threading.active_count()))  #Testing
                response = os.system("ping -n 1 " + addr)
                if response == 0:
                    print(addr, 'is up!')
                else:
                    print(addr, 'is down!')
                self.addrQueue.put(addr)
                print('Size: ', self.addrQueue.qsize()) #Testing
            except:
                print('Error during scan')

root = Tk()
app = NetworkMonitor(root)
root.geometry('400x400')
root.mainloop()