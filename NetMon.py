#Author: Dustin Grady
#Purpose: Monitor for changes to a network (dis/connections) and alert user.
#Status: In development


from tkinter import Tk, Scale, Button, Label
import threading
import queue
import os

class NetworkMonitor:
    def __init__(self, master):
        self.master = master
        master.title('Network Monitor v0.1')

        self.runScan = True
        self.MAX_THREADS = 128

        self.build_GUI()

        self.addrQueue = queue.Queue()
        [self.addrQueue.put(i) for i in['192.168.' + str(x) + '.' + str(y) for x in range(0, 256) for y in range(0, 256)]]

    '''Draw GUI elements'''
    def build_GUI(self):
        threadSlider = Scale(self.master, from_=1, to=self.MAX_THREADS, length=300, orient='horizontal')
        threadSlider.grid(row=0, column=1)

        threadLabel = Label(self.master, text="Threads")
        threadLabel.grid(row=1, column=1)

        start_button = Button(self.master, text="Start", command=lambda: self.start_Scan(threadSlider.get()))
        start_button.grid(row=2, column=0)

        stop_button = Button(self.master, text="Stop", command=lambda: self.stop_Scan())
        stop_button.grid(row=2, column=2)

    '''Using 16-bit IPv4 scheme'''
    def scan_Network(self):
        while not self.addrQueue.empty() and self.runScan:
            addr = self.addrQueue.get()
            try:
                #print("Threads: " + str(threading.active_count()), flush=True) #Show active thread count
                response = os.system("ping -n 1 " + addr + ' > nul') #Hide system ping output
                if response == 0:
                    print(addr, 'is up!', flush=True)
                    self.alert_User()
                else:
                    print(addr, 'is down!', flush=True)
                    #pass
                self.addrQueue.put(addr)
            except:
                print('Error during scan')

    '''Create multiple threads to accelerate pinging'''
    def start_Scan(self, THREAD_COUNT):
        self.runScan = True
        self.threads = {}
        for i in range(0, THREAD_COUNT):
            self.threads['thread' + str(i)] = threading.Thread(target=self.scan_Network)  # Create thread
            self.threads['thread' + str(i)].start()  # Start thread

    '''Cancel current scan'''
    def stop_Scan(self):
        self.runScan = False
        #self.master.quit()

    '''Send email to user'''
    def alert_User(self):
        print("Emailing user..")
        #self.stop_Scan() #Testing


root = Tk()
app = NetworkMonitor(root)
root.geometry('400x100')
root.mainloop()