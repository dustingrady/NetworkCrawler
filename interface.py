#Author: Dustin Grady
#Purpose: Draw GUI
#Status: In development
#To do:
#   -Clean up self declarations outside of init

from tkinter.ttk import Progressbar
import tkinter as tk
import threading
import scanner
import fileio
import utils


class GUI(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)  # Make sure to call this when overriding parent methods
        self.title('Network Crawler v0.1')
        GUI.build_gui(self)
        self.configuration = fileio.read_config()
        self.net_mon = scanner.NetworkMonitor(self)
        self.MAX_THREADS = 256
        GUI.update_status(self, 'Press "Start" to begin search')

    def build_gui(self):
        '''File menu'''
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Configure", command=self.config_window)
        file_menu.add_command(label="About", command=self.about_window)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=GUI.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        self.config(menu=menubar)

        '''Logo'''
        photo = tk.PhotoImage(file="./assets/logo.png")
        logo_label = tk.Label(self, image=photo)
        logo_label.grid(row=0, column=0, padx=50, pady=20)
        logo_label.image = photo

        '''Start/Stop buttons'''
        button_frame = tk.Frame(self)
        button_frame.grid(row=1, column=0, padx=50, pady=20)
        start_button = tk.Button(button_frame, text="Start", command=lambda: (start_button.config(state='disabled'), stop_button.config(state='normal'), self.net_mon.start_scan()))
        start_button.pack(side='left')
        stop_button = tk.Button(button_frame, text="Stop", command=lambda: (stop_button.config(state='disabled'), start_button.config(state='normal'), self.net_mon.stop_scan()))
        stop_button.pack(side='left')

        '''Results'''
        results_frame = tk.Frame(self)
        results_frame.grid(row=0, column=1)

        # Canvas
        results_canvas = tk.Canvas(results_frame, bd=0, width=625)
        results_canvas.pack(fill='both', side='left')

        # Display area
        self.results_view_area = tk.Frame(results_canvas)
        self.results_view_area.pack(side='top', fill='both')
        self.results_view_area.bind("<Configure>", lambda x: results_canvas.config(scrollregion=results_canvas.bbox("all")))  # Resize scroll region when widget size changes

        '''Progress'''
        progress_frame = tk.Frame(self)
        progress_frame.grid(row=1, column=1)

        # Current IP Address
        ip_progress_frame = tk.Frame(progress_frame)
        ip_progress_frame.grid(row=0, column=0)

        progress_canvas = tk.Canvas(ip_progress_frame, bd=0, height=15)
        progress_canvas.pack(side='left')

        self.progress_view_frame = tk.Frame(progress_canvas)
        self.progress_view_frame.pack(side='left')

        # IP Progress Bar/ Percentage
        progress_bar_frame = tk.Frame(progress_frame)
        progress_bar_frame.grid(row=0, column=1)

        self.scan_progress_bar = Progressbar(progress_bar_frame, orient='horizontal', length=275, mode='determinate')
        self.scan_progress_bar.grid(row=0, column=1, padx=30, sticky='ew')

        self.scan_percentage_frame = tk.Frame(progress_bar_frame)
        self.scan_percentage_frame.grid(row=0, column=1)

    '''Program description window'''
    def about_window(self):
        about_win = tk.Toplevel()
        about_win.wm_title("About")
        about_label = tk.Label(about_win,
                               text="Network Discovery Tool 2018\n A multithreaded network discovery tool designed to discover\n devices within a network and provide reports on the information gathered")
        about_label.grid(row=0, column=0, padx=15, pady=15)
        #about_win.geometry('325x70')
        about_win.grab_set()  # Modal
        about_win.resizable(False, False)

    '''Provides r/w access to config.ini'''
    def config_window(self):
        self.configuration = fileio.read_config()
        config_win = tk.Toplevel()
        config_frame = tk.Frame(config_win)
        config_win.wm_title("Configuration")
        config_label = tk.Label(config_frame, text="Configuration", font=('Helvetica', 10, 'bold')).pack(side='top')
        config_frame.grid(row=0, column=0)
        config_win.resizable(False, False)

        '''IP Prefix Selection'''
        ip_frame = tk.Frame(config_win)
        ip_desc_label = tk.Label(ip_frame, text="Network prefix ").pack(side='left')
        prefix1_val = tk.StringVar()
        prefix2_val = tk.StringVar()

        prefix1_val.set(self.configuration['IP_PREFIX'][0])
        prefix2_val.set(self.configuration['IP_PREFIX'][1])
        ip_prefix_form1 = tk.Entry(ip_frame, textvariable=prefix1_val, width=5).pack(side='left')
        dot = tk.Label(ip_frame, text=" . ").pack(side='left')
        ip_prefix_form2 = tk.Entry(ip_frame, textvariable=prefix2_val, width=5).pack(side='left')
        ip_suffix = tk.Label(ip_frame, text=" . X . X").pack(side='left')
        ip_frame.grid(row=1, column=0, pady=5, sticky='w')

        '''Reports'''
        report_frame = tk.Frame(config_win)
        report_label = tk.Label(report_frame, text="Report frequency ").pack(side='left')
        report_freq = ['Live', '1 hour', '6 hours', '12 hours', '24 hours', 'Never']
        freq_choice = tk.StringVar(self)
        freq_choice.set(self.configuration['REPORT'])
        freq_menu = tk.OptionMenu(report_frame, freq_choice, *report_freq).pack(side='left')
        report_frame.grid(row=2, column=0, pady=5, sticky='w')

        '''Discovery Type'''
        discovery_frame = tk.Frame(config_win)
        report_label = tk.Label(discovery_frame, text="Discovery method ").pack(side='left')
        disc_choice = tk.StringVar(self)
        disc_choice.set(self.configuration['DISCOVERY'])
        disc_menu = tk.OptionMenu(discovery_frame, disc_choice, *['ARP', 'Ping']).pack(side='left')
        discovery_frame.grid(row=3, column=0, pady=5, sticky='w')

        '''Thread Slider'''
        thread_frame = tk.Frame(config_win)
        thread_label = tk.Label(thread_frame, text="Threads").pack(side='left')
        thread_slider = tk.Scale(thread_frame, from_=1, to=self.MAX_THREADS, resolution=8, length=150,
                                 orient='horizontal')
        thread_slider.set(self.configuration['THREADS'])
        thread_slider.pack(side='left')
        thread_frame.grid(row=5, column=0, pady=5, sticky='w')

        '''Save Button'''
        save_button = tk.Button(config_win, text="Save", command=lambda: (fileio.save_config(prefix1_val.get(), prefix2_val.get(), freq_choice.get(), disc_choice.get(), thread_slider.get()), config_win.destroy()))  # Could probably be cleaned up (pass dict?)
        save_button.grid(row=6, column=0, pady=5)

        config_win.grab_set()  # Modal

    '''Updates results_window'''
    def build_result(self):
        tree = tk.ttk.Treeview(self.results_view_area, height=7, columns=('IP', 'MAC', 'Vendor'))
        tree.heading('#0', text='IP')
        tree.heading('#1', text='MAC')
        tree.heading('#2', text='Vendor')
        tree.heading('#3', text='Details')

        tree.column('#0', minwidth=125, width=125, stretch=False)
        tree.column('#1', minwidth=125, width=125, stretch=False)
        tree.column('#2', minwidth=150, width=150, stretch=False)
        tree.column('#3', minwidth=125, width=125, stretch=False)

        tree.grid(row=0, column=1, sticky='nsew')

        style = tk.ttk.Style(self.results_view_area)
        style.configure('Treeview', rowheight=25)

        for i, rec in enumerate(self.net_mon.record_list):
            tree.insert('', 'end', tags='evenrow' if i % 2 else 'oddrow', text=str(rec.ip), values=(str(rec.mac), str(rec.oui)))
            details_button = tk.Button(self.results_view_area, text="Details", command=lambda i=i: GUI.details_window(self, self.net_mon.record_list[i]))
            details_button.place(x=430, y=(i+1)*25, width=75)
        tree.tag_configure('evenrow', background='gray80')
        tree.tag_configure('oddrow', background='gray60')

    '''Clear our results'''
    def clear_result_window(self):
        for widget in self.results_view_area.winfo_children():
            widget.destroy()

    '''Update progress of scan'''
    def update_status(self, status, scan_count=0):
        ip_label = tk.Label(self.progress_view_frame, text=status)
        if scan_count:
            self.scan_progress_bar['value'] = ((65536-scan_count)/65536)*100  # Update progress/ loading bar here
            #percentage_label = tk.Label(self.scan_percentage_frame, text=format((float((65536-scan_count)/65536)*100), '.3f') + ' %', font=('Helvetica', '7'))  # Update percentage here
            #percentage_label.grid(row=0, column=0)
        ip_label.grid(row=0, column=0, sticky='ew')

    '''Show more details of a device'''
    def details_window(self, record):
        details_win = tk.Toplevel()
        details_win.title('Details')

        self.details_frame = tk.Frame(details_win)
        self.details_frame.pack(side='top')

        self.progress_label = tk.Label(self.details_frame, text="Gathering information..")
        self.progress_label.grid(row=0, column=0, columnspan=2)

        self.details_progress_bar = Progressbar(self.details_frame, orient='horizontal', length=100, mode='determinate')
        self.details_progress_bar.grid(row=1, column=0, padx=30, columnspan=2, sticky='ew')

        self.ip_label = tk.Label(self.details_frame, text="IP Address:")
        self.ip_result_label = tk.Label(self.details_frame, text="Loading..")
        self.ip_label.grid(row=2, column=0, padx=10, sticky='w')
        self.ip_result_label.grid(row=2, padx=10, column=1, sticky='w')

        self.mac_label = tk.Label(self.details_frame, text="MAC Address:")
        self.mac_result_label = tk.Label(self.details_frame, text="Loading..")
        self.mac_label.grid(row=3, column=0, padx=10, sticky='w')
        self.mac_result_label.grid(row=3, padx=10, column=1, sticky='w')

        self.oui_label = tk.Label(self.details_frame, text="Vendor:")
        self.oui_result_label = tk.Label(self.details_frame, text="Loading..")
        self.oui_label.grid(row=4, column=0, padx=10, sticky='w')
        self.oui_result_label.grid(row=4, padx=10, column=1, sticky='w')

        self.os_label = tk.Label(self.details_frame, text="OS/ Accuracy:")
        self.os_result_label = tk.Label(self.details_frame, text="Loading..")
        self.os_label.grid(row=5, column=0, padx=10, sticky='w')
        self.os_result_label.grid(row=5, padx=10, column=1, sticky='w')

        self.port_label = tk.Label(self.details_frame, text="Port Status:")
        self.port_placeholder_label = tk.Label(self.details_frame, text="Loading..")
        self.port_label.grid(row=6, column=0, padx=10, sticky='w')
        self.port_placeholder_label.grid(row=6, padx=10, column=1, sticky='w')

        self.details_thread = threading.Thread(target=lambda: (GUI.build_details(self, record)))  # Start thread to get results
        self.details_thread.start()

        details_win.grab_set()  # Modal
        details_win.resizable(False, False)

    def build_details(self, record):
        self.ip_result_label.config(text=str(record.ip))
        self.details_progress_bar['value'] = 10

        self.mac_result_label.config(text=str(record.mac))
        self.details_progress_bar['value'] = 20

        self.oui_result_label.config(text=str(record.oui))
        self.details_progress_bar['value'] = 30

        record.op_sys, record.op_acc = utils.retrieve_os(record)
        self.net_mon.record_list[(utils.get_record_index(record.ip, self.net_mon.record_list))].op_sys = record.op_sys  # Update record object
        self.net_mon.record_list[(utils.get_record_index(record.ip, self.net_mon.record_list))].op_acc = record.op_acc
        self.os_result_label.config(text=record.op_sys + '/ ' + record.op_acc + '%')
        self.details_progress_bar['value'] = 70

        try:
            for i, port in enumerate(utils.retrieve_port_status(record)):
                self.net_mon.record_list[(utils.get_record_index(record.ip, self.net_mon.record_list))].ports.append(port)
                self.port_placeholder_label.config(text="")
                self.port_result_label = tk.Label(self.details_frame)
                self.port_result_label.config(text=port)
                self.port_result_label.grid(row=i+6, column=1, sticky='w')
        except TypeError:
            self.port_placeholder_label.config(text="None detected")
        self.details_progress_bar['value'] = 100
        self.progress_label.config(text="Scan complete")

    '''
    def error_window(self, msg):
        tk.messagebox.showinfo("Error", msg)
    '''


if __name__ == '__main__':
    app = GUI()
    app.geometry('925x275')
    app.resizable(False, False)
app.mainloop()
