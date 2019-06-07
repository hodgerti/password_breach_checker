###############################################
# The plan
###############################################
'''
'''

###############################################
# Imports
###############################################
import os
from copy import deepcopy
from hashlib import sha1
import threading
import Queue
import Tkinter as tk
import tkFileDialog
import _winreg
import time
from datetime import datetime
from sys import platform

###############################################
# Definitions
###############################################
HASH_LENGTH = len("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
AVG_LINE_LENGTH = len(":1\n") + HASH_LENGTH

BRUTE_MODE      = 0x00
SORT_MODE       = 0x01
ALL_MOD         = 0x10
MODS            = [ALL_MOD]

# set_mods(mode, [ALL_MOD])
def set_mods(mode, mods):
    mode = mode & 0x0F
    for mod in mods:
        mode |= mod
    return mode

def get_mods(mode):
    mods_used = []
    for mod in MODS:
        if (mode & 0xF0) == mod:
            mods_used.append(mod)
    return mods_used

def get_mode(mode):
    return mode & 0x0F


###############################################
# Types
###############################################
class Entry_Ex(tk.Entry):
    def __init__(self, **kwargs):
        self.content = None
        if 'textvariable' not in kwargs.keys():
            self.content = tk.StringVar()
            self.content.set('')
            kwargs['textvariable'] = self.content
        tk.Entry.__init__(self, **kwargs)

    def set(self, text):
        if self.content is not None:
            self.content.set(text)
        else:
            assert "Non internal content assigned"

    def get(self):
        if self.content is not None:
            return self.content.get()
        else:
            assert "Non internal content assigned"

class DataThread(threading.Thread):
    def __init__(self, sor, eor, match_queue, hashed, filename, found_event, mode):
        super(DataThread, self).__init__()
        self.waiting = threading.Event()
        self.sor = sor
        self.eor = eor
        self.match_queue = match_queue
        self.hashed = hashed
        self.filename = filename
        self.found_event = found_event
        self.mode = mode

        self.characters_read = 0

        self.file_size = os.path.getsize(filename)

    def run(self):
        with open(self.filename, 'r') as f_in:
            f_in.seek(self.sor+1, os.SEEK_SET)
            while not self.found_event.is_set():
                place = f_in.tell()
                if place < self.eor:
                    self.characters_read = place - self.sor
                    line = f_in.readline()
                    hashed = line[:HASH_LENGTH]
                    if self.hashed == hashed:
                        result = int(line[HASH_LENGTH+1:].strip())
                        self.match_queue.put(result)
                        if ALL_MOD not in get_mods(self.mode):
                            self.found_event.set()
                            break
                else:
                    break

class MatchHash(threading.Thread):

    def __init__(self, password, filename, num_threads, num_splits, mode):
        super(MatchHash, self).__init__()
        self.match_queue = Queue.Queue()
        self.hashed = hash_password(password)
        self.mode = mode
        only_mode = get_mode(self.mode)
        if only_mode == BRUTE_MODE:
            self.splits, self.num_threads = make_splits(filename, num_threads)
        elif only_mode == SORT_MODE:
            self.splits, self.num_threads = make_splits_sort(filename, self.hashed, num_splits, num_threads)
        else:
            self.splits, self.num_threads = make_splits_sort(filename, self.hashed, num_splits, num_threads)

        self.enum = 0
        self.denum = self.splits[-1] - self.splits[0]

        self.filename = filename

        self.found_event = threading.Event()
        self.found_event.clear()
        self.finished_event = threading.Event()
        self.finished_event.clear()

        self.threads = []

        self.matches = None
        self.start_time = None
        self.elapsed_time = None

    def run(self):
        self.finished_event.clear()
        self.start_time = time.time()
        self.matches = 0

        # make worker threads
        old_split = self.splits[0]
        for split in self.splits[1:]:
            thread = DataThread(old_split, split, self.match_queue, self.hashed, self.filename, self.found_event, self.mode)
            self.threads.append(thread)
            old_split = split + 1
            thread.start()

        # wait until worker threads are done
        thread_count = len([thread.is_alive() for thread in self.threads])
        thread_count_old = thread_count
        while thread_count > 0:
            thread_count = len([thread for thread in self.threads if thread.is_alive()])
            if thread_count != thread_count_old:
                thread_count_old = thread_count
            if self.found_event.is_set():
                break
        self.elapsed_time = self.get_elapsed_time()
        self.matches = self.get_matches()
        self.finished_event.set()

    def get_enum(self):
        self.enum = 0
        for thread in self.threads:
            self.enum += thread.characters_read
        return self.enum

    def get_matches(self):
        while not self.match_queue.empty():
            self.matches += self.match_queue.get()
        return self.matches

    def get_elapsed_time(self):
        self.elapsed_time = time.time() - self.start_time
        return self.elapsed_time

    def stop(self):
        self.found_event.set()

    def check_finished(self):
        return self.finished_event.is_set()

    def wait_till_finished(self):
        self.finished_event.wait()

class MatchHashGUI(tk.Frame):
    REGISTRY_LOCATION = "Software\\CS_472\\Hash_checker\\Settings"
    PROGRESS_UPDT_PERIOD = 20
    PROGRESS_BAR_LENGTH = 84

    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.master = master
        self.master.protocol("WM_DELETE_WINDOW", self.handle_close)

        self.breach_file  = tk.StringVar()
        self.window_width = tk.IntVar()
        self.window_height = tk.IntVar()

        self.match_hash = None
        self.progress_bar_characters = chr(178)*self.PROGRESS_BAR_LENGTH

        self.linux = False
        self.windows = False

        self.build_gui()

    def build_gui(self):
        HEIGHT = 100
        WIDTH = 575

        row = 0
        col = 0
        pwd_label = tk.Label(self.master, text="Password:")
        pwd_label.grid(row=row, column=col, sticky='e')
        self.pwd = Entry_Ex(master=self.master, width=50)
        self.pwd.grid(row=row, column=col+1, sticky='w', rowspan=1)
        self.pwd.set("")

        row = 1
        col = 0
        breaches_label = tk.Label(self.master, text="Breaches:")
        breaches_label.grid(row=row, column=col, sticky='e')
        self.breaches = Entry_Ex(master=self.master, width=50)
        self.breaches.grid(row=row, column=col+1, sticky='w', rowspan=1)
        self.breaches.set("")

        row = 2
        col = 0
        search_time_label = tk.Label(self.master, text="Time (s):")
        search_time_label.grid(row=row, column=col, sticky='e')
        self.search_time = Entry_Ex(master=self.master, width=50)
        self.search_time.grid(row=row, column=col+1, sticky='w', rowspan=1)
        self.search_time.set("")

        row = 0
        col = 2
        num_threads_label = tk.Label(self.master, text="Threads:")
        num_threads_label.grid(row=row, column=col, sticky='e')
        self.num_threads = tk.StringVar()
        self.num_threads.set("80")
        self.num_threads_entry = tk.Spinbox(self.master, from_=2, to=999, width=3, textvariable=self.num_threads)
        self.num_threads_entry.grid(row=row, column=col+1, sticky='w')

        row = 1
        col = 2
        num_splits_label = tk.Label(self.master, text="Splits:")
        num_splits_label.grid(row=row, column=col, sticky='e')
        self.num_splits = tk.StringVar()
        self.num_splits.set("15")
        self.num_splits_entry = tk.Spinbox(self.master, from_=1, to=100, width=3, textvariable=self.num_splits)
        self.num_splits_entry.grid(row=row, column=col+1, sticky='w')

        row = 2
        col = 2
        self.do_brute = tk.IntVar()
        self.brute_button = tk.Checkbutton(self.master, text='Brute', variable=self.do_brute)
        self.brute_button.grid(row=row, column=col, columnspan=2, sticky='w')

        row = 2
        col = 2
        self.do_sort = tk.IntVar()
        self.sort_button = tk.Checkbutton(self.master, text='Sorted', variable=self.do_sort)
        self.sort_button.grid(row=row, column=col, columnspan=2)
        self.sort_button.select()

        row = 2
        col = 2
        self.do_all = tk.IntVar()
        self.all_button = tk.Checkbutton(self.master, text='All', variable=self.do_all)
        self.all_button.grid(row=row, column=col, columnspan=2, sticky='e')

        row = 3
        col = 0
        progress_label = tk.Label(self.master, text="Progress:")
        progress_label.grid(row=row, column=col, sticky='e')
        self.progress = Entry_Ex(master=self.master, width=self.PROGRESS_BAR_LENGTH, state=tk.DISABLED)
        self.progress.grid(row=row, column=col + 1, sticky='w', rowspan=1, columnspan=3)
        self.progress.set("")

        menubar = tk.Menu(self.master)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open Breach File", command=self.load_breach_file)
        menubar.add_cascade(label="File", menu=filemenu)
        menubar.add_command(label="GO!", command=self.run)
        menubar.add_command(label="STOP!", command=self.stop)
        self.master.config(menu=menubar)

        self.window_width.set(WIDTH)
        self.window_height.set(HEIGHT)

        self.init()
        self.master.geometry('{}x{}'.format(self.window_width.get(), self.window_height.get()))

    def open_registry(self):
        return _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, self.REGISTRY_LOCATION)

    def get_registry_table(self):
        return [
                ("Window_width",   self.window_width,       _winreg.REG_DWORD),
                ("Window_height",  self.window_height,      _winreg.REG_DWORD),
                ("Brute",          self.do_brute,           _winreg.REG_DWORD),
                ("Sort",           self.do_sort,            _winreg.REG_DWORD),
                ("All",            self.do_all,             _winreg.REG_DWORD),
                ("Breach_file",    self.breach_file,        _winreg.REG_SZ),
                ("Num_threads",    self.num_threads,        _winreg.REG_SZ),
                ("Num_splits",     self.num_splits,         _winreg.REG_SZ),
               ]

    def init(self):
        if platform == "linux" or platform == "linux2":
            self.linux = True
        else:
            self.windows = True
        if self.windows:
            table = self.get_registry_table()
            try:
                settings = self.open_registry()
                for key, var, format in table:
                    try:
                        value, actual_format = _winreg.QueryValueEx(settings, key)
                        if actual_format == format:
                            var.set(value)
                    except:
                        pass

                _winreg.CloseKey(settings)
            except:
                pass

    def stop(self):
        if self.match_hash is not None:
            self.match_hash.stop()

    def handle_close(self):
        if self.match_hash is not None:
            self.match_hash.stop()
        self.window_width.set(self.master.winfo_width())
        self.window_height.set(self.master.winfo_height())
        if self.windows:
            table = self.get_registry_table()
            try:
                settings = self.open_registry()
                for key, var, format in table:
                    if format == _winreg.REG_SZ:
                        value = str(var.get())
                    elif format == _winreg.REG_DWORD:
                        value = int(var.get())
                    _winreg.SetValueEx(settings, key, 0, format, value)
                _winreg.CloseKey(settings)
            finally:
                self.master.destroy()

    def load_breach_file(self):
        if self.breach_file.get() and os.path.exists(os.path.dirname(self.breach_file.get())):
            initialdir = os.path.dirname(self.breach_file.get())
        else:
            initialdir = os.getcwd()
        iop_defs = tkFileDialog.askopenfilename(parent=self.master,
                                                title='Select breaches.txt',
                                                initialdir=initialdir,
                                                filetypes=[('', 'txt')])
        if os.path.exists(iop_defs):
            self.breach_file.set(iop_defs)

    def disable(self):
        self.pwd['state'] = tk.DISABLED
        self.breaches['state'] = tk.DISABLED
        self.search_time['state'] = tk.DISABLED
        self.num_threads_entry['state'] = tk.DISABLED
        self.num_splits_entry['state'] = tk.DISABLED
        self.brute_button['state'] = tk.DISABLED
        self.sort_button['state'] = tk.DISABLED
        self.all_button['state'] = tk.DISABLED


    def enable(self):
        self.pwd['state'] = tk.NORMAL
        self.breaches['state'] = tk.NORMAL
        self.search_time['state'] = tk.NORMAL
        self.num_threads_entry['state'] = tk.NORMAL
        self.num_splits_entry['state'] = tk.NORMAL
        self.brute_button['state'] = tk.NORMAL
        self.sort_button['state'] = tk.NORMAL
        self.all_button['state'] = tk.NORMAL

    def manage_progress(self):
        self.breaches.set(self.match_hash.get_matches())
        time_passed = self.match_hash.get_elapsed_time()
        value_passed = datetime.utcfromtimestamp(time_passed)
        exact_time_passed = value_passed.strftime('%H:%M:%S:%f')
        if self.match_hash.check_finished():
            self.enable()
            self.progress.set("")
            self.search_time.set(exact_time_passed)
        else:
            # update progress bar
            enum = self.match_hash.get_enum()
            denum = self.match_hash.denum
            percent_done = float(enum) / float(denum)
            num_bars = int(percent_done * self.PROGRESS_BAR_LENGTH)
            if percent_done > 0.0:
                value_to_go = datetime.utcfromtimestamp(time_passed/percent_done)
            else:
                value_to_go = datetime.utcfromtimestamp(time_passed)
            exact_time_to_go = value_to_go.strftime('%H:%M:%S:%f')

            self.search_time.set("{} / {}".format(exact_time_passed, exact_time_to_go))
            self.progress.set(self.progress_bar_characters[:num_bars])
            self.after(self.PROGRESS_UPDT_PERIOD, self.manage_progress)

    def run(self):
        if self.do_brute.get():
            mode = BRUTE_MODE
        elif self.do_sort.get():
            mode = SORT_MODE
        else:
            mode = SORT_MODE
        if self.do_all.get():
            mode = set_mods(mode, [ALL_MOD])

        self.disable()
        self.breaches.set("")
        self.search_time.set("")
        self.match_hash = MatchHash(self.pwd.get(),
                               self.breach_file.get(),
                               int(self.num_threads.get()),
                               int(self.num_splits.get()),
                               mode)
        self.num_threads.set(self.match_hash.num_threads)
        self.match_hash.start()
        self.manage_progress()

###############################################
# Functions
###############################################

# SHA-1's password
def hash_password(password):
    hasher = sha1()
    hasher.update(password)
    hashed = hasher.hexdigest()
    return hashed.upper()

# checks that split denotes a '\n'
def check_splits(splits, f_name):
    with open(f_name) as f_in:
        for split in splits:
            f_in.seek(split, os.SEEK_SET)
            c = f_in.read(1)
            if c == '\n':
                continue
            if not c:
                return False, c
    return True, '\n'


def make_splits(f_name, num_threads):
    # create a list of split locations using average size of a hash
    # ---
    file_size = os.path.getsize(f_name)
    # correct range of splits
    if (file_size / AVG_LINE_LENGTH) < num_threads:
        num_threads = file_size / AVG_LINE_LENGTH
    splits = range(0, file_size, file_size/num_threads)
    splits = splits[1:]  # remove '0' at beginning
    # correct list of splits
    f_in = open(f_name, 'r')
    for idx, val in enumerate(deepcopy(splits)):
        f_in.seek(val, os.SEEK_SET)
        offset = 0
        while True:
            offset += 1
            c = f_in.read(1)
            if c == '\n':
                break
            if not c:
                break
        splits[idx] += offset
    f_in.close()
    return splits, num_threads

def make_splits_sort(f_name, hashed, num_splits, num_threads):
    jump_iterations = num_splits
    top = 0
    bottom = os.path.getsize(f_name)
    with open(f_name) as f_in:
        for jum_num in range(0, jump_iterations):
            # go to middle of area and move to start of line
            middle = top + ( (bottom - top) / 2 )
            f_in.seek(middle, os.SEEK_SET)
            while True:
                c = f_in.read(1)
                if c == '\n':
                    break
                if not c:
                    break
            # check if need to move up or down
            line = f_in.readline()
            line_hash = line[:HASH_LENGTH]
            sorted_hashs = sorted([line_hash, hashed])
            # move up
            if hashed == sorted_hashs[0]:
                bottom = f_in.tell()
            # move down
            else:
                top = f_in.tell()
    # create a list of split locations using average size of a hash
    # ---
    # correct range of splits
    split_range = bottom - top
    if (split_range / AVG_LINE_LENGTH) < num_threads:
        num_threads = split_range / AVG_LINE_LENGTH
    splits = range(top, bottom, split_range/num_threads)
    # correct list of splits
    f_in = open(f_name, 'r')
    for idx, val in enumerate(deepcopy(splits)):
        f_in.seek(val, os.SEEK_SET)
        offset = 0
        while True:
            offset += 1
            c = f_in.read(1)
            if c == '\n':
                break
            if not c:
                break
        splits[idx] += offset
    f_in.close()
    # checks_out, _ = check_splits(splits, f_name)
    # print(checks_out)
    return splits, num_threads

if __name__== "__main__":
    # Start the GUI
    root = tk.Tk()
    app = MatchHashGUI(root)
    root.title('Breach Checker')
    root.mainloop()


