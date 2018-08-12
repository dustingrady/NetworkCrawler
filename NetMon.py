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

        self.addrQueue = queue.Queue()
        [self.addrQueue.put(i) for i in ['192.168.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]

        self.Cancel = False
        self.THREAD_COUNT = 8
        self.build_GUI()

    '''Draw GUI elements'''
    def build_GUI(self):
        self.scan_button = Button(self.master, text="Scan", command=lambda: self.build_Threads(self.THREAD_COUNT))
        self.scan_button.grid(row=0, column=1)

        self.cancel_button = Button(self.master, text="Cancel", command=lambda: self.cancel_Scan())
        self.cancel_button.grid(row=1, column=1)

    def build_Threads(self, THREAD_COUNT):
        self.threads = {}
        for i in range(0, THREAD_COUNT):
            self.threads['thread' + str(i)] = threading.Thread(target=self.scan_Network) #Create thread
            self.threads['thread' + str(i)].start() #Start thread

    '''Using 16-bit IPv4 scheme'''
    def scan_Network(self):
        while not self.addrQueue.empty() and not self.Cancel:
            addr = self.addrQueue.get()
            try:
                print('Address: ', addr)  #Testing
                print("Threads: " + str(threading.active_count())) #Testing

                response = os.system("ping -n 1 " + addr)
                if response == 0:
                    print(addr, 'is up!')
                else:
                    print(addr, 'is down!')
                    self.alert_User()
                self.addrQueue.put(addr)
                print('Size: ', self.addrQueue.qsize()) #Testing
            except:
                print('Error during scan')

    '''Cancel current scan'''
    def cancel_Scan(self):
        self.Cancel = True
        self.master.quit()

    '''Send email to user'''
    def alert_User(self):
        print("Emailing user..")


root = Tk()
app = NetworkMonitor(root)
root.geometry('200x200')
root.mainloop()