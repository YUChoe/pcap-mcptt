# -*- coding: utf-8 -*-

import pyshark
import tkinter as tk
import tkinter.font as tkfont
# import json
import hashlib
import os
import pickle
import time
import sys


tracking_ipaddrs = []
# tracking_ipaddrs.append('10.100.1.120')  # terminal
# tracking_ipaddrs.append('175.223.18.165')  # syj LTE terminal
# tracking_ipaddrs.append('10.100.1.27')  # terminal
tracking_ipaddrs.append('223.62.212.32')

tracking_ipaddrs.append('27.1.48.212')  # SBC-ext
tracking_ipaddrs.append('10.200.1.5')  # SBC-int

tracking_ipaddrs.append('10.200.1.80')  # CSCF
tracking_ipaddrs.append('27.1.48.217')  # MRU


def gethash(s):
    return hashlib.sha256(s.encode()).hexdigest()


def output(packet):
    proto = packet.layers[2]
    print(f'{packet.sniff_time} {packet.ip.src:<15}:{proto.srcport:>5} - {packet.ip.dst:<15}:{proto.dstport:>5}')


def output_briefly(packet):
    print(f"{packet['time']} {packet['sip']} - {packet['dip']}")


def save_as_json(pcap_filename):
    st = time.time()
    print(f'Start: {pcap_filename}')
    j = []
    with pyshark.FileCapture(pcap_filename) as pcap:
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
                        d['udp'] = packet
                        j.append(d)
    print(f'Parsed: {time.time() - st}')

    print(f'Saving:{pcap_filename}.pkl')
    st = time.time()
    with open(f'{pcap_filename}.pkl', 'wb') as fp:
        pickle.dump(j, fp)
    print(f'Finished: {time.time() - st}')


class AppWindow():
    def __init__(self, win):
        self.win = win
        self.canvas = tk.Canvas(self.win)
        sbar = tk.Scrollbar(self.win)
        sbar.config(command=self.canvas.yview)
        self.canvas.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<ButtonRelease-1>", self._on_click)
        self.canvas.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)
        self.canvas_width = 750

        self.font = tkfont.Font(family="Consolas", size=9)
        self.font2 = tkfont.Font(family="Consolas", size=8)

        self.text = tk.Text(win, width=90, height=100, font=self.font2)
        self.text.pack(side='right')

        self.sip_methods = ['REGISTER', 'INVITE', 'REFER']
        self.row_count = 0

        # static value for testing
        s1 = ['223.62.212.32', '10.100.1.120', '175.223.18.165', '10.100.1.27']
        s2 = ['27.1.48.212']
        s3 = ['10.200.1.5']
        s4 = ['10.200.1.80']
        s5 = ['27.1.48.217']
        self.slots = [s1, s2, s3, s4, s5]

        self.datas = []
        # self.fflag = True
        self.pcaps = {}

    def _on_click(self, event):
        x = event.x
        y = event.y
        ts, pcap = self.which_pcap(x, y)
        if pcap:
            udp = pcap['pcap']['udp']
            self.text.insert(1.0, udp)

    def which_pcap(self, x, y):
        for ts, p in self.pcaps.items():
            if p['y1'] <= y <= p['y2']:
                return ts, p
        else:
            return None, None

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def get_slotnum_by_ip(self, ipaddr):
        for s in self.slots:
            # print(ipaddr, 'in', s)
            if ipaddr in s:
                return self.slots.index(s)
        return 0

    def xpos_by_slotnum(self, sn):
        return sn * 120 + 300

    def _draw_on_canvas(self, pos_x, pos_y, s):
        self.canvas.create_text(pos_x+100, pos_y, text=s, font=self.font2)

    def _draw(self, pos_x, pos_y, s):
        slot = tk.Label(self.win, text=s, font=self.font)
        slot.place(x=pos_x, y=pos_y)

    def draw(self, t, sip, sport, dip, dport, pcap):
        y = self.row_count * 16 + 30

        # background
        if self.row_count % 2:
            self.canvas.create_rectangle(0, y-5, self.canvas_width, y+5, outline="#FFF", fill="#FFF")

        self.pcaps[t] = {
                'x1': 0, 'y1': y - 5,
                'x2': self.canvas_width, 'y2': y + 5,
                'pcap': pcap}

        # slot 0: timestamp
        self._draw_on_canvas(10, y, f'{t} ({pcap["udp"].length})')
        sslotnum = self.get_slotnum_by_ip(sip)
        dslotnum = self.get_slotnum_by_ip(dip)

        # line
        xoffset = 45
        yoffset = 0
        self.canvas.create_line(
            self.xpos_by_slotnum(sslotnum) + xoffset, y + yoffset,
            self.xpos_by_slotnum(dslotnum) + xoffset, y + yoffset)

        # SIP
        sip_msg = ''
        if 'udp' in pcap and 'sip' in pcap['udp']:
            if hasattr(pcap['udp'].sip, 'method'):
                sip_msg = str(pcap['udp'].sip.method).strip()
            else:
                sip_msg = str(pcap['udp'].sip.cseq).strip().split()[1]

            if sip_msg in self.sip_methods:
                if hasattr(pcap['udp'].sip, 'status_code'):
                    sip_msg = str(pcap['udp'].sip.status_code)

        # arrow
        if sslotnum < dslotnum:
            # left to right
            self.canvas.create_line(
                self.xpos_by_slotnum(dslotnum) + xoffset, y + yoffset,
                self.xpos_by_slotnum(dslotnum) + xoffset - 7, y + yoffset - 3)
            # left portnum sport
            self.canvas.create_text(
                self.xpos_by_slotnum(sslotnum) + xoffset - 20, y + yoffset,
                text=f'{str(sport):>5}', font=self.font2)
            # right portnum sport
            self.canvas.create_text(
                self.xpos_by_slotnum(dslotnum) + xoffset + 20, y + yoffset,
                text=f'{str(dport):<5}', font=self.font2)
            # sip_msg
            if sip_msg:
                self.canvas.create_text(
                    self.xpos_by_slotnum(sslotnum) + xoffset + 20 + 7, y + yoffset - 5,
                    text=f'{sip_msg:<8}', font=self.font2)
        else:
            # right to left
            self.canvas.create_line(
                self.xpos_by_slotnum(dslotnum) + xoffset, y + yoffset,
                self.xpos_by_slotnum(dslotnum) + xoffset + 7, y + yoffset - 3)
            # left portnum sport
            self.canvas.create_text(
                self.xpos_by_slotnum(sslotnum) + xoffset + 20, y + yoffset,
                text=f'{str(sport):<5}', font=self.font2)
            # right portnum sport
            self.canvas.create_text(
                self.xpos_by_slotnum(dslotnum) + xoffset - 20, y + yoffset,
                text=f'{str(dport):>5}', font=self.font2)
            # sip_msg
            if sip_msg:
                self.canvas.create_text(
                    self.xpos_by_slotnum(sslotnum) + xoffset - 20 - 5, y + yoffset - 5,
                    text=f'{sip_msg:>8}', font=self.font2)

        self.row_count += 1

    def update_height(self):
        y = self.row_count * 16 + 30
        self.canvas.config(scrollregion=(0, 0, self.canvas_width, y + 100))

        # ipaddr on app
        xoffset = 45
        for slotnum, slot in enumerate(self.slots):
            self._draw(self.xpos_by_slotnum(slotnum), 0, f'{slot[0]}')
            # vertical lines on canvas
            self.canvas.create_line(
                self.xpos_by_slotnum(slotnum) + xoffset, 7,
                self.xpos_by_slotnum(slotnum) + xoffset, y + 50)


__version = '3'


if __name__ == '__main__':
    w = tk.Tk()
    app = AppWindow(w)
    w.geometry("1270x800+150+150")
    w.title(f'MCPTT-pcap parser v{__version}')
    w.resizable(True, True)

    if len(sys.argv) < 2:
        pcap_filepath = 't1.pcap'
    else:
        pcap_filepath = sys.argv[1]

    if not os.path.isfile(f'{pcap_filepath}.pkl'):
        save_as_json(pcap_filepath)

    bt = time.time()
    j = []

    with open(f'{pcap_filepath}.pkl', 'rb') as fp:
        j = pickle.load(fp)
    print('loading time: ', time.time() - bt)

    i = 0
    for packet in j:
        # output(packet['pcap'])
        app.draw(packet['time'], packet['sip'], packet['sport'], packet['dip'], packet['dport'], packet)
        i += 1
        # if i > 200:
        #     break
    print('total packets:', i)
    app.update_height()

    w.mainloop()
