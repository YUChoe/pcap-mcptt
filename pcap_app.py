# -*- coding: utf-8 -*-

import pyshark
import tkinter as tk
import tkinter.font as tkfont
# import json
import hashlib
import os
import pickle
import time


tracking_ipaddrs = []
tracking_ipaddrs.append('10.100.1.120')  # terminal
tracking_ipaddrs.append('175.223.18.165')  # syj LTE terminal
# tracking_ipaddrs.append('10.100.1.27')  # terminal

tracking_ipaddrs.append('27.1.48.212')  # SBC-ext
tracking_ipaddrs.append('10.200.1.5')  # SBC-int

tracking_ipaddrs.append('10.200.1.80')  # CSCF
tracking_ipaddrs.append('27.1.48.217')  # MRU

pcapfiles = []
# pcapfiles.append('invite_success_sip00.pcap')
# pcapfiles.append('dump-20200113-190506.pcap')
# pcapfiles.append('dump-20200113-203316.pcap')
# pcapfiles.append('dump-20200113-203532.pcap')
pcapfiles.append('t1.pcap')


def gethash(s):
    return hashlib.sha256(s.encode()).hexdigest()


def output(packet):
    proto = packet.layers[2]
    print(f'{packet.sniff_time} {packet.ip.src:<15}:{proto.srcport:>5} - {packet.ip.dst:<15}:{proto.dstport:>5}')


def output_briefly(packet):
    print(f"{packet['time']} {packet['sip']} - {packet['dip']}")


def save_as_json(pcap_filename):
    j = []
    for pcapfilename in pcapfiles:
        with pyshark.FileCapture(pcapfilename) as pcap:
            for packet in pcap:
                if 'IP' in packet:
                    proto = packet.layers[2]
                    if proto.layer_name == 'udp':
                        if packet.ip.src in tracking_ipaddrs and packet.ip.dst in tracking_ipaddrs:
                            d = {}
                            d['time'] = str(packet.sniff_time)
                            d['sip'] = str(packet.ip.src)
                            d['sport'] = int(proto.srcport)
                            d['dip'] = str(packet.ip.dst)
                            d['dport'] = int(proto.dstport)
                            d['pcap'] = packet  # pickle.dumps(packet)
                            j.append(d)
                            # output(packet)
    with open('pcap.pkl', 'wb') as fp:
        pickle.dump(j, fp)


class AppWindow():
    def __init__(self, win):
        self.win = win
        self.canvas = tk.Canvas(self.win)
        # self.canvas.config(scrollregion=(0, 0, 800, 3000))
        sbar = tk.Scrollbar(self.win)
        sbar.config(command=self.canvas.yview)
        self.canvas.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)

        self.font = tkfont.Font(family="Consolas", size=9)
        self.font2 = tkfont.Font(family="Consolas", size=8)

        self.row_count = 0
        # self.slots = []

        # static value for testing
        s1 = ['10.100.1.120', '175.223.18.165', '10.100.1.27']
        s2 = ['27.1.48.212']
        s3 = ['10.200.1.5']
        s4 = ['10.200.1.80']
        s5 = ['27.1.48.217']
        self.slots = [s1, s2, s3, s4, s5]

        self.datas = []
        # self.fflag = True

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def get_slotnum_by_ip(self, ipaddr):
        for s in self.slots:
            # print(ipaddr, 'in', s)
            if ipaddr in s:
                return self.slots.index(s)
        return 0

    def xpos_by_slotnum(self, sn):
        return sn * 150 + 250

    def _draw_on_canvas(self, pos_x, pos_y, s):
        self.canvas.create_text(pos_x+100, pos_y, text=s, font=self.font)

    def _draw(self, pos_x, pos_y, s):
        slot = tk.Label(self.win, text=s, font=self.font)
        slot.place(x=pos_x, y=pos_y)

    def draw(self, t, sip, sport, dip, dport):
        y = self.row_count * 16 + 30

        # background
        if self.row_count % 2:
            self.canvas.create_rectangle(0, y-5, 1000, y+5, outline="#FFF", fill="#FFF")

        # slot 0: timestamp
        self._draw_on_canvas(30, y, t)
        sslotnum = self.get_slotnum_by_ip(sip)
        dslotnum = self.get_slotnum_by_ip(dip)

        # line
        xoffset = 45
        yoffset = 0
        self.canvas.create_line(
            self.xpos_by_slotnum(sslotnum) + xoffset, y + yoffset,
            self.xpos_by_slotnum(dslotnum) + xoffset, y + yoffset)

        # arrow
        if sslotnum < dslotnum:
            # left to right
            self.canvas.create_line(
                self.xpos_by_slotnum(sslotnum) + xoffset, y + yoffset,
                self.xpos_by_slotnum(sslotnum) + xoffset + 5, y + yoffset - 3)
            # left portnum sport
            self.canvas.create_text(self.xpos_by_slotnum(sslotnum) + xoffset - 20, y + yoffset,
                text=f'{str(sport):>5}', font=self.font2)
            # right portnum sport
            self.canvas.create_text(self.xpos_by_slotnum(dslotnum) + xoffset + 20, y + yoffset,
                text=f'{str(dport):<5}', font=self.font2)
        else:
            # right to left
            self.canvas.create_line(
                self.xpos_by_slotnum(sslotnum) + xoffset, y + yoffset,
                self.xpos_by_slotnum(sslotnum) + xoffset - 5, y + yoffset - 3)
            # left portnum sport
            self.canvas.create_text(self.xpos_by_slotnum(dslotnum) + xoffset - 20, y + yoffset,
                text=f'{str(sport):>5}', font=self.font2)
            # right portnum sport
            self.canvas.create_text(self.xpos_by_slotnum(sslotnum) + xoffset + 20, y + yoffset,
                text=f'{str(dport):<5}', font=self.font2)

        self.row_count += 1

    def update_height(self):
        y = self.row_count * 16 + 30
        self.canvas.config(scrollregion=(0, 0, 1000, y + 100))

        # ipaddr on app
        xoffset = 45
        for slotnum, slot in enumerate(self.slots):
            self._draw(self.xpos_by_slotnum(slotnum), 0, f'{slot[0]}')
            # vertical lines on canvas
            self.canvas.create_line(
                self.xpos_by_slotnum(slotnum) + xoffset, 7,
                self.xpos_by_slotnum(slotnum) + xoffset, y + 50)



if __name__ == '__main__':
    if not os.path.isfile('pcap.pkl'):
        save_as_json('t1.pcap')

    bt = time.time()
    j = []
    with open('pcap.pkl', 'rb') as fp:
        j = pickle.load(fp)
    print('loading time: ', time.time() - bt)

    w = tk.Tk()
    app = AppWindow(w)
    w.geometry("1000x600+200+200")
    w.title('MCPTT-pcap parser v1')
    w.resizable(True, True)

    i = 0
    for packet in j:
        # output(packet['pcap'])
        app.draw(packet['time'], packet['sip'], packet['sport'], packet['dip'], packet['dport'])
        i += 1
        # if i > 200:
        #     break
    print('total packets:', i)
    app.update_height()

    w.mainloop()
