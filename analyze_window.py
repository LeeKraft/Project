#!/usr/bin/python3
import subprocess
import datetime
import re
import os
import glob
from more_itertools import only
import pymongo
import json
import pyshark
from threading import Thread
from tkinter import *
from tkinter import messagebox
from tkinter.ttk import Combobox
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog
import collections
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from psql import *

class AnalyzeWindow:
    delimiter = '-' * 92
    basic_options = ['',
                    'Краткую информацию по пакетам',
                    'Статистику использования сетевых протоколов',
                    'Статистику посещения интернет ресурсов',
                    'Объем входящего и исходящего трафика',
                    'Статистику посещения подозрительных сайтов',
                    'Использование незащищенных протоколов']
    file = str()
    packets = pyshark.FileCapture
    running = False
    mac = list()
    def __init__(self, parent):
        self.root = Toplevel(parent)
        self.root.title("Анализ трафика")
        self.root.geometry('{}x{}+{}+{}'.format(1400, 700, self.root.winfo_screenwidth()//2 - 700, self.root.winfo_screenheight()//2 - 350))
        self.root.resizable(False,False)
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        # menu
        mainmenu = Menu(self.root) 
        self.root.configure(menu=mainmenu)
        filemenu = Menu(mainmenu, tearoff=0)
        filemenu.add_command(label="Открыть", command=self.open_file)
        helpmenu = Menu(mainmenu, tearoff=0)
        helpmenu.add_command(label="О программе", command=self.show_info)
        mainmenu.add_cascade(label="Файл", menu=filemenu)
        mainmenu.add_cascade(label="Помощь", menu=helpmenu)
        # frame
        self.frm_options = LabelFrame(master=self.root, width=500, height=150, relief=SUNKEN, borderwidth=5, bg="#e9ffe3", font=("Arial",12,"bold"), text="Параметры")
        self.frm_graph = LabelFrame(master=self.root, width=900, height=700, relief=SUNKEN, borderwidth=5, bg="#e9ffe3", font=("Arial",12,"bold"), text="График")
        self.frm_report = LabelFrame(master=self.root, width=500, height=400, relief=SUNKEN, borderwidth=5, bg="#e9ffe3", font=("Arial",12,"bold"), text="Отчёт")
        self.frm_status = LabelFrame(master=self.root, width=500, height=150, relief=SUNKEN, borderwidth=5, bg="#e9ffe3", font=("Arial",12,"bold"), text="Статус")
        # options
        self.lbl_basic = Label(master=self.frm_options, text="Показать:", font=("Arial",14), bg="#e9ffe3")
        self.lbl_basic.place(relx=0.05, rely=0.04)
        self.cmb_basic = Combobox(master=self.frm_options, width=43, font=("Arial",13), values=self.basic_options, state="readonly")
        self.cmb_basic.place(relx=0.05, rely=0.3)
        self.btn_load = Button(master=self.frm_options, width=15, text="Загрузить данные", font=("Arial",14), command=self.load)
        self.btn_load.place(relx=0.05, rely=0.6)
        self.btn_execute = Button(master=self.frm_options, width=10, text="Выполнить", font=("Arial",14), command=self.execute)
        self.btn_execute.place(relx=0.7, rely=0.6)
        # graph
        self.figure = plt.Figure(dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, self.frm_graph)
        self.canvas.get_tk_widget().place(x=0, y=0, width = 890, height = 675)
        # report
        self.txt_report = ScrolledText(master=self.frm_report, width=52, height=19, wrap=WORD, font=("Arial",12), state=DISABLED)
        self.txt_report.place(x=0, y=0)
        # status
        self.txt_status = ScrolledText(master=self.frm_status, width=52, height=6, wrap=WORD, font=("Arial",12), state=DISABLED)
        self.txt_status.place(x=0, y=0)

        self.frm_options.place(x=0, y=0)
        self.frm_graph.place(x=500, y=0)
        self.frm_report.place(x=0, y=300)
        self.frm_status.place(x=0, y=150)

        self.root.transient(parent)
        self.root.grab_set()
        self.root.focus_set()
        self.root.wait_window()
    
    def on_close(self):
        plt.close("all")
        self.root.destroy()

    def open_file(self):
        self.txt_status.configure(state=NORMAL)
        self.file = filedialog.askopenfilename(initialdir="dump/", filetypes=(("PCAP files","*.pcap*"),))
        if self.file:
            self.txt_status.insert(END, "Выбран файл:\n")
            self.txt_status.insert(END, f"{os.path.basename(r'{}'.format(str(self.file)))}\n")
        self.txt_status.configure(state=DISABLED)
    
    def load(self):
        self.txt_status.configure(state=NORMAL)
        if not self.file:
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Сначала выберите файл для обработки.\n")
            self.txt_status.configure(state=DISABLED)
            return
        if not self.running:
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт выгрузка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.read_pcap)
            self.running=True
            thread.start()
        self.txt_status.configure(state=DISABLED)
    
    def read_pcap(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        connection = connect()
        create_table(connection)
        self.packets = pyshark.FileCapture(self.file, keep_packets=False)
        str_flags = ['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
        icmp_type = {'0': 'Echo reply', '3': 'Destination unreachable', '4': 'Source quench', '5': 'Redirect', '8': 'Echo request', '9': 'Router advertisement', '10': 'Router selection', '11': 'Time exceeded', '12': 'Parameter problem', '13': 'Timestamp', '14': 'Timestamp reply', '15': 'Information request', '16': 'Information reply', '17': 'Address mask request', '18': 'Address mask reply', '30': 'Traceroute'}
        def save_packets(packet):
            info = None
            if packet.highest_layer == "TCP":
                if 'flags' in packet.tcp.field_names:
                    flags = [f.start() for f in re.finditer('1', bin(int(packet.tcp.flags, 16))[2:].zfill(9))]
                    info = ", ".join([str_flags[item] for item in flags])
                if "IPv6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, packet.tcp.srcport, packet.tcp.dstport, info)
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport, info)
            elif packet.highest_layer == "DATA" and 'UDP' in packet:
                if "IPv6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, 'UDP', packet.ipv6.src, packet.ipv6.dst, packet.udp.srcport, packet.udp.dstport, 'Data')
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, 'UDP', packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport, 'Data')
            elif packet.highest_layer == 'UDP':
                if "IPv6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, packet.udp.srcport, packet.udp.dstport, None)
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport, None)
            elif packet.highest_layer == "DNS":
                if "IPv6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, None, None, packet.dns.qry_name)
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, None, None, packet.dns.qry_name)
            elif packet.highest_layer == "ICMP":
                if 'type' in packet.icmp.field_names:
                    info = icmp_type.get(packet.icmp.type)
                if "IPv6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, None, None, info)
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, None, None, info)
            elif packet.highest_layer == "TLS" and packet.tls.field_names != []:
                if 'record' in packet.tls.field_names:
                    info = " ".join(packet.tls.record.split()[3:])
                if "IPV6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, None, None, info)
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, None, None, info)
            elif packet.highest_layer == "ARP":
                if 'opcode' in packet.arp.field_names and packet.arp.opcode == '1':
                    info = f"ARP Request. Who has {packet.arp.dst_proto_ipv4}? Tell {packet.arp.src_proto_ipv4}"
                elif 'opcode' in packet.arp.field_names and packet.arp.opcode == '2':
                    info = f"ARP Reply. {packet.arp.src_proto_ipv4} is at {packet.arp.src_hw_mac}"
                put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, None, None, None, None, info)
            elif "HTTP" in packet:
                if 'chat' in packet.http.field_names:
                    info = packet.http.chat[:-4]
                if 'host' in packet.http.field_names:
                    info = info + f" Host: {packet.http.host}"
                elif 'content_type' in packet.http.field_names:
                    info = info + f" Content-type: {packet.http.content_type}"
                if "IPV6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, "HTTP", packet.ipv6.src, packet.ipv6.dst, None, None, info)
                if "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, "HTTP", packet.ip.src, packet.ip.dst, None, None, info)
            else:
                if "IPv6" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, None, None, None)
                elif "IP" in packet:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, None, None, None)
                else:
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, None, None, None, None, None)
        self.packets.apply_on_packets(save_packets)
        self.packets.close()
        self.packets.eventloop.stop()
        connection.close()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные загружены.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)
    
    def execute(self):
        self.txt_status.configure(state=NORMAL)
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM packet")
        if cursor.rowcount:
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, f"В базе найдены данные.\nКоличество записей - {cursor.rowcount}.\n")
            self.txt_status.configure(state=DISABLED)
            cursor.close()
            connection.close()
        else:
            cursor.close()
            connection.close()
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Сначала выберите файл для обработки.\n")
            self.txt_status.configure(state=DISABLED)
            return
        if not self.cmb_basic.current():
            self.txt_status.configure(state=NORMAL)
            self.txt_status.insert(END, "Выберите действие из списка.\n")
            self.txt_status.configure(state=DISABLED)
            return
        if self.cmb_basic.current() == 1 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.show_brief_info)
            self.running=True
            thread.start()
        if self.cmb_basic.current() == 2 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.show_stat_proto)
            self.running=True
            thread.start()
        if self.cmb_basic.current() == 3 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.show_stat_site)
            self.running=True
            thread.start()
        if self.cmb_basic.current() == 4 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.traffic_volume)
            self.running=True
            thread.start()
        if self.cmb_basic.current() == 5 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.suspicious)
            self.running=True
            thread.start()   
        if self.cmb_basic.current() == 6 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.unsecure)
            self.running=True
            thread.start()      

        # files_to_delete = glob.glob('dump/splitted/*')
        # for file in files_to_delete:
        #     os.remove(file)
        # for item in self.files:
        #     self.split_pcap(item)
        # files_to_json = os.listdir('dump/splitted')
        # files_to_json.sort()
        # for file in files_to_json:
        #     thread = Thread(target=self.pcap_to_json, args=(file,), daemon=True)
        #     thread.start()
    
        self.txt_status.configure(state=DISABLED)

    def suspicious(self):
        # ДОДЕЛАТЬ ЧТОБ НЕ ПОВТОРЯЛИСЬ ЗНАЧЕНИЯ В СПИСКЕ 
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        self.packets = pyshark.FileCapture(self.file, display_filter="dns")
        dns = []
        for packet in self.packets:
            dns.append(packet.dns.qry_name)
        hosts = open('suspicious_hosts')
        count = 0
        n = 0
        reg = re.compile('[^a-zA-Z.]')
        bad_hosts = []
        for line in hosts.readlines():
            line = re.sub(r'\[[^][]*\]', '', line)
            if line != '\n':
                bad_hosts.append(reg.sub('', line))
        self.txt_report.delete("1.0", END)
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, " Сведения о посещениях нежелательных интернет ресурсов.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tРесурс\n\n")
        for row in dns:
            try:
                n += 1
                if row in bad_hosts:
                    self.txt_report.insert(END, f"{row}\n")
                    count += 1
            except IndexError:
                pass
        self.txt_report.insert(END, f"Процент посещения нежелательных ресурсов: {round(count * 100.0 / n, 2)} %.")
        hosts.close()
        self.packets.close()
        self.packets.eventloop.stop()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def unsecure(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        self.packets = pyshark.FileCapture(self.file, display_filter="http.host")
        hostName = []
        for packet in self.packets:
            if "HTTP" in packet:
                hostName.append(packet.http.host)
        counter = collections.Counter(hostName)
        counter = dict(sorted(counter.items(), key=lambda x: x[0]))
        self.txt_report.delete("1.0", END)
        if len(hostName):
            self.txt_report.insert(END, f"{self.delimiter}\n")
            self.txt_report.insert(END, "\tДоступ к интернет ресурсам по протоколу HTTP.\n")
            self.txt_report.insert(END, f"{self.delimiter}\n")
            self.txt_report.insert(END, "\tРесурс\t\tКоличество посещений\n\n")
            for key, value in counter.items():
                self.txt_report.insert(END, f"{key}\t\t\t\t{value}\n")
        else:
            self.txt_report.insert(END, "Интернет ресурсы работающие по протоколу HTTP не обнаружены.\n")
        self.packets.close()
        self.packets.eventloop.stop()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def get_mac(self):
        try:
            mac = subprocess.run('ip a | grep ether | gawk \'{print $2}\'', shell=True, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if mac.returncode:
                messagebox.showerror("Ошибка", f"Не удалось определить MAC-адрес устройства.\nПрограмма выдала ошибку: {mac.stderr}")
            else:
                self.mac = mac.stdout.split()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось определить MAC-адрес устройства.\nПрограмма выдала исключение: {str(e)}")

    def traffic_volume(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        self.get_mac()
        self.packets = pyshark.FileCapture(self.file, keep_packets=False)
        inner = {'length': [], 'time': []}
        outer = {'length': [], 'time': []}
        def save_packets(packet):
            if packet.eth.src in self.mac:
                outer['length'].append(int(packet.length))
                outer['time'].append(packet.sniff_time)
            if packet.eth.dst in self.mac:
                inner['length'].append(int(packet.length))
                inner['time'].append(packet.sniff_time)
        self.packets.apply_on_packets(save_packets)
        if not len(inner['length']) or not len(outer['length']):
            messagebox.showerror("Ошибка", f"MAC адреса вашего устойства нет в выбранном файле.\n")
            return
        inner_volume = 0
        outer_volume = 0
        in_unit = "Б"
        out_unit = "Б"
        for item in inner['length']:
            inner_volume += item
        for item in outer['length']:
            outer_volume += item
        if 3 < len(str(inner_volume)) < 7:
            inner_volume /= 1024
            inner_volume = round(inner_volume, 2)
            in_unit = "КБ"
        if 3 < len(str(outer_volume)) < 7:
            outer_volume /= 1024
            outer_volume = round(outer_volume, 2)
            out_unit = "КБ"
        if 6 < len(str(inner_volume)) < 10:
            inner_volume /= pow(1024, 2)
            inner_volume = round(inner_volume, 2)
            in_unit = "МБ"
        if 6 < len(str(outer_volume)) < 10:
            outer_volume /= pow(1024, 2)
            outer_volume = round(outer_volume, 2)
            out_unit = "МБ"
        if 10 < len(str(inner_volume)) < 14:
            inner_volume /= pow(1024, 3)
            inner_volume = round(inner_volume, 2)
            in_unit = "ГБ"
        if 10 < len(str(outer_volume)) < 14:
            outer_volume /= pow(1024, 3)
            outer_volume = round(outer_volume, 2)
            out_unit = "ГБ"
        self.txt_report.delete("1.0", END)
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tСведения об объеме сетевого трафика.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, f"Объем входящего трафика: {inner_volume} {in_unit}.\nОбъем исходящего трафика: {outer_volume} {out_unit}.")
        ingraph = self.figure.add_subplot(211)
        outgraph = self.figure.add_subplot(212)
        self.figure.tight_layout(pad=5)
        ingraph.set(xlabel='Время', ylabel='Объем (байты)', title='Входящий трафик')
        outgraph.set(xlabel='Время', ylabel='Объем (байты)', title='Исходящий трафик')
        ingraph.grid()
        outgraph.grid()
        ingraph.plot(inner['time'], inner['length'], color='b')
        outgraph.plot(outer['time'], outer['length'], color='r')
        in_pos = np.arange(0, max(inner['length']) + (max(inner['length']) - min(inner['length']))//8, (max(inner['length']) - min(inner['length']))//8)
        out_pos = np.arange(0, max(outer['length']) + (max(outer['length']) - min(outer['length']))//8, (max(outer['length']) - min(outer['length']))//8)
        ingraph.set_yticks(in_pos)
        outgraph.set_yticks(out_pos)
        self.canvas.draw()
        self.packets.close()
        self.packets.eventloop.stop()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)


    def show_stat_site(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        self.packets = pyshark.FileCapture(self.file, display_filter="dns")
        siteList = []
        for packet in self.packets:
            siteList.append(packet.dns.qry_name)
        counter = collections.Counter(siteList)
        counter = dict(sorted(counter.items(), key=lambda x: x[1], reverse=True))
        self.txt_report.delete("1.0", END)
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tСведения о посещениях интернет ресурсов.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tРесурс\t\tКоличество посещений\n\n")
        for key, value in counter.items():
            self.txt_report.insert(END, f"{key}\t\t\t\t{value}\n")
        self.packets.close()
        self.packets.eventloop.stop()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def show_stat_proto(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        self.packets = pyshark.FileCapture(self.file, only_summaries=True)
        protocolList = []
        for packet in self.packets:
            line = str(packet).split()
            protocolList.append(line[4])
        protocolList.sort()
        counter = collections.Counter(protocolList)
        self.txt_report.delete("1.0", END)
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, " Сведения об использовании протоколов передачи данных.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "Протокол\t\tКоличество\n\n")
        for key, value in counter.items():
            self.txt_report.insert(END, f"{key}\t\t{value}\n")
        graph = self.figure.add_subplot(111)
        self.figure.tight_layout(pad=5)
        y_pos = np.arange(len(list(counter.keys())))
        graph.set_title("Частота использования сетевых протоколов")
        graph.set_ylabel("Частота")
        graph.set_xlabel("Протокол")
        graph.bar(y_pos, list(counter.values()), align='center', alpha=0.5, color=['b', 'g', 'r', 'c', 'm'])
        graph.set_xticks(y_pos, list(counter.keys()), rotation=-45, fontsize=7)
        self.canvas.draw()
        self.packets.close()
        self.packets.eventloop.stop()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def show_brief_info(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM packet")
        self.txt_report.delete("1.0", END)
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tКраткие сведения о сетевых пакетах.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, f"Количество пакетов в файле: {cursor.rowcount}.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        rows = cursor.fetchall()
        line = str()
        for row in rows:
            
            self.txt_report.insert(END, line)
            print(row)
        cursor.close()
        connection.close()
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)
        
    def pyshark_read(self, _filter: str, _summaries: bool):
        pass

    def split_pcap(self, file: str):
        try:
            editcap = subprocess.run(['editcap', '-c', '10000', file, 'dump/splitted/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if editcap.returncode:
                messagebox.showerror("Ошибка", f"Не удалось разделить файл: {os.path.basename(r'{}'.format(str(file)))}.\nПрограмма выдала ошибку: {editcap.stderr}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось переформатировать данные.\nПрограмма выдала исключение: {str(e)}")

    def pcap_to_json(self, file: str):
        try:
            tshark = subprocess.run(f'tshark -r dump/splitted/{file} -T json > dump/splitted/{file}.json', shell=True, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if tshark.returncode:
                messagebox.showerror("Ошибка", f"Не удалось переформатировать файл: {os.path.basename(r'{}'.format(str(file)))}.\nПрограмма выдала ошибку: {tshark.stderr}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось переформатировать данные.\nПрограмма выдала исключение: {str(e)}")

    def show_info(self):
        pass