#!/usr/bin/python3
import subprocess #nosec
import datetime
import re
import os
import pyshark
from threading import Thread
from tkinter import END, NORMAL, WORD, DISABLED, SUNKEN, Toplevel, Menu, LabelFrame, Label, Button, messagebox, filedialog
from tkinter.ttk import Combobox
from tkinter.scrolledtext import ScrolledText
import collections
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from psql import connect, create_table, put_data

class AnalyzeWindow:
    bg_color = "#e4eff2"
    delimiter = '-' * 92
    basic_options = ['',
                    'Краткую информацию по пакетам',
                    'Статистику использования сетевых протоколов',
                    'Статистику посещения сетевых ресурсов',
                    'Объем входящего и исходящего трафика',
                    'Статистику посещения подозрительных сайтов',
                    'Использование незащищенных протоколов',
                    'Проверка наличия угроз безопасности']
    file = str()
    packets = pyshark.FileCapture
    running = False
    mac = list()
    user = str()
    def __init__(self, parent):
        """
        Sets all the necessary attributes for an object of the AnalyzeWindow class
        """
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
        self.frm_options = LabelFrame(master=self.root, width=500, height=150, relief=SUNKEN, borderwidth=5, bg=self.bg_color, font=("Arial",12,"bold"), text="Параметры")
        self.frm_graph = LabelFrame(master=self.root, width=900, height=700, relief=SUNKEN, borderwidth=5, bg=self.bg_color, font=("Arial",12,"bold"), text="График")
        self.frm_report = LabelFrame(master=self.root, width=500, height=400, relief=SUNKEN, borderwidth=5, bg=self.bg_color, font=("Arial",12,"bold"), text="Отчёт")
        self.frm_status = LabelFrame(master=self.root, width=500, height=150, relief=SUNKEN, borderwidth=5, bg=self.bg_color, font=("Arial",12,"bold"), text="Статус")
        # options
        self.lbl_basic = Label(master=self.frm_options, text="Показать:", font=("Arial",14), bg=self.bg_color)
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
        # start_time = datetime.datetime.now()
        connection = connect()
        create_table(connection)
        self.packets = pyshark.FileCapture(self.file, keep_packets=False)
        str_flags = ['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
        icmp_type = {'0': 'Echo reply', '3': 'Destination unreachable', '4': 'Source quench', '5': 'Redirect', '8': 'Echo request', '9': 'Router advertisement', '10': 'Router selection', '11': 'Time exceeded', '12': 'Parameter problem', '13': 'Timestamp', '14': 'Timestamp reply', '15': 'Information request', '16': 'Information reply', '17': 'Address mask request', '18': 'Address mask reply', '30': 'Traceroute'}
        icmp_du_code = {'0': 'Net is unreachable', '1': 'Host is unreachable', '2': 'Protocol is unreachable', '3': 'Port is unreachable'}
        def save_packets(packet):
            info = None
            proto = None
            try:
                if packet.highest_layer == "TCP":
                    if 'flags' in packet.tcp.field_names:
                        flags = [f.start() for f in re.finditer('1', bin(int(packet.tcp.flags, 16))[2:].zfill(9))]
                        info = ", ".join([str_flags[item] for item in flags])
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, packet.tcp.srcport, packet.tcp.dstport, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport, info)
                elif packet.highest_layer == "DATA" and 'TCP' in packet:
                    if 'flags' in packet.tcp.field_names:
                        flags = [f.start() for f in re.finditer('1', bin(int(packet.tcp.flags, 16))[2:].zfill(9))]
                        info = ", ".join([str_flags[item] for item in flags])
                    proto = "TCP"
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ipv6.src, packet.ipv6.dst, packet.tcp.srcport, packet.tcp.dstport, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport, info)
                elif packet.highest_layer == "DATA" and 'UDP' in packet:
                    proto = "UDP"
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ipv6.src, packet.ipv6.dst, packet.udp.srcport, packet.udp.dstport, 'Data')
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport, 'Data')
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
                    if 'type' in packet.icmp.field_names and 'code' in packet.icmp.field_names:
                        info = icmp_type.get(packet.icmp.type)
                        if packet.icmp.type == '3' and int(packet.icmp.code) < 4:
                            info = info + ' - ' + icmp_du_code.get(packet.icmp.code)
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, None, None, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, None, None, info)
                elif packet.highest_layer != "ICMP" and 'ICMP' in packet:
                    proto = 'ICMP'
                    if 'type' in packet.icmp.field_names and 'code' in packet.icmp.field_names:
                        info = icmp_type.get(packet.icmp.type)
                        if packet.icmp.type == '3' and int(packet.icmp.code) < 4:
                            info = info + ' - ' + icmp_du_code.get(packet.icmp.code)
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ipv6.src, packet.ipv6.dst, None, None, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ip.src, packet.ip.dst, None, None, info)
                elif packet.highest_layer == "TLS" and packet.tls.field_names != []:
                    if 'record' in packet.tls.field_names:
                        info = " ".join(packet.tls.record.split()[3:])
                        proto = packet.tls.record.split()[0]
                    else:
                        proto = "TLS"
                    if "IPV6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ipv6.src, packet.ipv6.dst, None, None, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ip.src, packet.ip.dst, None, None, info)
                elif packet.highest_layer == "ARP":
                    if 'opcode' in packet.arp.field_names and packet.arp.opcode == '1':
                        info = f"ARP Request. Who has {packet.arp.dst_proto_ipv4}? Tell {packet.arp.src_proto_ipv4}"
                    elif 'opcode' in packet.arp.field_names and packet.arp.opcode == '2':
                        info = f"ARP Reply. {packet.arp.src_proto_ipv4} is at {packet.arp.src_hw_mac}"
                    put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, None, None, None, None, info)
                elif "HTTP" in packet:
                    proto = "HTTP"
                    if 'chat' in packet.http.field_names:
                        info = packet.http.chat[:-4]
                    if 'host' in packet.http.field_names:
                        info = info + f" Host: {packet.http.host}"
                    elif 'content_type' in packet.http.field_names:
                        info = info + f" Content-type: {packet.http.content_type}"
                    if "IPV6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ipv6.src, packet.ipv6.dst, None, None, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ip.src, packet.ip.dst, None, None, info)
                elif "QUIC" in packet:
                    proto = "QUIC"
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ipv6.src, packet.ipv6.dst, packet.udp.srcport, packet.udp.dstport, None)
                    elif "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, proto, packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport, None)
                elif packet.highest_layer == '_WS.MALFORMED':
                    if packet.transport_layer == "TCP":
                        if 'flags' in packet.tcp.field_names:
                            flags = [f.start() for f in re.finditer('1', bin(int(packet.tcp.flags, 16))[2:].zfill(9))]
                            info = ", ".join([str_flags[item] for item in flags])
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.transport_layer, packet.ipv6.src, packet.ipv6.dst, packet[packet.transport_layer].srcport, packet[packet.transport_layer].dstport, info)
                    if "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.transport_layer, packet.ip.src, packet.ip.dst, packet[packet.transport_layer].srcport, packet[packet.transport_layer].dstport, info)
                else:
                    if "IPv6" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ipv6.src, packet.ipv6.dst, None, None, None)
                    elif "IP" in packet:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, packet.ip.src, packet.ip.dst, None, None, None)
                    else:
                        put_data(connection, packet.sniff_time, packet.length, packet.eth.src, packet.eth.dst, packet.highest_layer, None, None, None, None, None)
            except Exception as e:
                print(e)
        self.packets.apply_on_packets(save_packets)
        self.packets.close()
        self.packets.eventloop.stop()
        # end_time = datetime.datetime.now()
        # f = open('loading_time.txt', 'a')
        # cursor = connection.cursor()
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"File: {self.file} Rows: {str(cursor.rowcount)} LoadTime: {end_time - start_time}\n")
        # f.close()
        # cursor.close()
        connection.close()
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные загружены.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)
    
    def execute(self):
        self.txt_status.configure(state=NORMAL)
        if self.running:
            return
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
            thread = Thread(target=self.insecure)
            self.running=True
            thread.start()   
        if self.cmb_basic.current() == 7 and not self.running:
            self.txt_status.configure(state=NORMAL)
            self.txt_status.delete("1.0", END)
            self.txt_status.insert(END, "Идёт обработка данных...\n")
            self.txt_status.configure(state=DISABLED)
            thread = Thread(target=self.threat)
            self.running=True
            thread.start()       
        self.txt_status.configure(state=DISABLED)

    def threat(self):
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        try:
            ip = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if not ip.returncode:
                self.user = ip.stdout.split()[0]
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось узнать IP адрес.\nПрограмма выдала исключение: {str(e)}")
        # start_t = datetime.datetime.now()
        connection = connect()
        cursor = connection.cursor()
        self.txt_report.delete("1.0", END)
        # ARP scanning
        cursor.execute("SELECT time, info FROM packet WHERE dstmac = 'ff:ff:ff:ff:ff:ff' and info LIKE 'ARP Request%'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1].split()[-1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки ARP сканирования.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество ARP запросов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # IP Protocol scan
        cursor.execute("SELECT time, dstip FROM packet WHERE info LIKE 'Destination unreachable - Protocol is unreachable'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования IP протоколов (портов).\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество ICMP ответов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # ICMP ping sweeps
        cursor.execute("SELECT time, srcip, dstip, info FROM packet WHERE info LIKE 'Echo request' or info LIKE 'Echo reply'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                if row[3] == 'Echo request':
                    record['addr'].append(row[1])
                if row[3] == 'Echo reply':
                    record['addr'].append(row[2])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования доступности узлов по IP адресу.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество ICMP запросов/ответов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # TCP ping sweeps
        cursor.execute("SELECT time, srcip FROM packet WHERE proto LIKE 'TCP' and dstport=7")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования доступности узлов с помощью протокола TCP.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество TCP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # UDP ping sweeps
        cursor.execute("SELECT time, srcip FROM packet WHERE proto LIKE 'UDP' and dstport=7")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования доступности узлов с помощью протокола UDP.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество UDP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # TCP SYN scan
        cursor.execute("SELECT time, srcip FROM packet WHERE proto LIKE 'TCP' and info LIKE '%SYN%' and info not LIKE '%ACK%'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования портов с помощью протокола TCP SYN.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество TCP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # TCP Null scan
        cursor.execute("SELECT time, srcip FROM packet WHERE proto LIKE 'TCP' and info LIKE ''")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования портов с помощью протокола TCP Null.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество TCP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # TCP FIN scan
        cursor.execute("SELECT time, srcip FROM packet WHERE proto LIKE 'TCP' and info LIKE 'FIN'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования портов с помощью протокола TCP FIN.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество TCP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # TCP Xmass scan
        cursor.execute("SELECT time, srcip FROM packet WHERE proto LIKE 'TCP' and info LIKE 'URG, PSH, FIN'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования портов с помощью протокола TCP Xmass.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество TCP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # UDP port scan
        cursor.execute("SELECT time, dstip FROM packet WHERE info LIKE 'Destination unreachable - Port is unreachable'")
        rows = cursor.fetchall()
        record = {'time': [], 'addr': []}
        if cursor.rowcount:
            for row in rows:
                record['addr'].append(row[1])
                try:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    record['time'].append(datetime.datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
            addr = collections.Counter(record['addr'])
            attacker = addr.most_common(1)
            start_time = str(record['time'][record['addr'].index(attacker[0][0])])
            record['time'].reverse()
            record['addr'].reverse()
            end_time = str(record['time'][record['addr'].index(attacker[0][0])])
            if attacker[0][0] != self.user:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки сканирования портов с помощью протокола UDP.\nIP адрес злоумышленника: {str(attacker[0][0])}\nКоличество UDP пакетов: {str(attacker[0][1])}\nНачало атаки: {start_time}\nКонец атаки: {end_time}\n")
        # DoS
        cursor.execute("SELECT srcmac, dstmac FROM packet WHERE proto LIKE 'IP'")
        rows = cursor.fetchall()
        record = {}
        if cursor.rowcount:
            for row in rows:
                record[row[0]] = set()
            for row in rows:
                record[row[0]].add(row[1])
        for key, value in record.items():
            if len(value) > 1:
                self.txt_report.insert(END, f"{self.delimiter}\n")
                self.txt_report.insert(END, f"Обнаружены признаки DoS атаки.\nMAC адрес злоумышленника: {key}\nКоличество полученных пакетов: {str(len(value))}")
        if self.txt_report.get(0.0, END).strip() == '':
            self.txt_report.insert(END, "Угрозы безопасности не выявлены.\n")
        # timer
        # end_t = datetime.datetime.now()
        # f = open('threat_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_t - start_t}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def suspicious(self):
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        # start_time = datetime.datetime.now()
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT info FROM packet WHERE proto LIKE 'DNS'")
        rows = cursor.fetchall()
        dns = []
        for row in rows:
            dns.append(row[0])
        hosts = open('suspicious_hosts')
        count = 0
        n = 0
        reg = re.compile('[^a-zA-Z.]')
        bad_hosts = []
        for line in hosts.readlines():
            line = re.sub(r'\[[^][]*\]', '', line)
            if line != '\n':
                bad_hosts.append(reg.sub('', line))
        dns_temp = []
        for row in dns:
            try:
                n += 1
                if row in bad_hosts:
                    dns_temp.append(row)
                    count += 1
            except IndexError:
                pass
        counter_dns = collections.Counter(dns_temp)
        self.txt_report.delete("1.0", END)
        if count:
            self.txt_report.insert(END, f"{self.delimiter}\n")
            self.txt_report.insert(END, " Сведения о посещениях нежелательных сетевых ресурсов.\n")
            self.txt_report.insert(END, f"{self.delimiter}\n")
            self.txt_report.insert(END, f"Процент посещения нежелательных ресурсов: {round(count * 100.0 / n, 2)} %.\n")
            self.txt_report.insert(END, "\tРесурс\n")
            for key in counter_dns.keys():
                self.txt_report.insert(END, f"{str(key)}\n")
        else:
            self.txt_report.insert(END, "Данные по посещениям нежелательных сетевых ресурсов не выявлены.\n")
        hosts.close()
        # timer
        # end_time = datetime.datetime.now()
        # f = open('suspicious_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_time - start_time}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def insecure(self):
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        # start_time = datetime.datetime.now()
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT info FROM packet WHERE info LIKE '%Host%'")
        rows = cursor.fetchall()
        hostName = []
        for row in rows:
            hostName.append(row[0].split()[-1])
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
        # timer
        # end_time = datetime.datetime.now()
        # f = open('insecure_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_time - start_time}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
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
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        self.get_mac()
        # start_time = datetime.datetime.now()
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT srcmac, dstmac, time, length FROM packet")
        rows = cursor.fetchall()
        inner = {'length': [], 'time': []}
        outer = {'length': [], 'time': []}
        for row in rows:
            if row[0] in self.mac:
                outer['length'].append(row[3])
                try:
                    outer['time'].append(datetime.datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    outer['time'].append(datetime.datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S'))
            if row[1] in self.mac:
                inner['length'].append(row[3])
                try:
                    inner['time'].append(datetime.datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S.%f'))
                except ValueError:
                    inner['time'].append(datetime.datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S'))
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
        indelta = (inner['time'][-1] - inner['time'][0]) / 5
        ingraph.set_xticks([inner['time'][0] + indelta * i for i in range(6)])
        outdelta = (outer['time'][-1] - outer['time'][0]) / 5
        outgraph.set_xticks([outer['time'][0] + outdelta * i for i in range(6)])
        in_pos = np.arange(0, max(inner['length']) + (max(inner['length']) - min(inner['length']))//8, (max(inner['length']) - min(inner['length']))//8)
        out_pos = np.arange(0, max(outer['length']) + (max(outer['length']) - min(outer['length']))//8, (max(outer['length']) - min(outer['length']))//8)
        ingraph.set_yticks(in_pos)
        outgraph.set_yticks(out_pos)
        date_form = DateFormatter("%H:%M:%S\n%d.%m.%Y")
        ingraph.xaxis.set_major_formatter(date_form)
        outgraph.xaxis.set_major_formatter(date_form)
        self.canvas.draw()
        # timer
        # end_time = datetime.datetime.now()
        # f = open('traffic_volume_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_time - start_time}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def show_stat_site(self):
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        # start_time = datetime.datetime.now()
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT info FROM packet WHERE proto LIKE 'DNS'")
        rows = cursor.fetchall()
        siteList = []
        for row in rows:
            siteList.append(row[0])
        counter = collections.Counter(siteList)
        counter = dict(sorted(counter.items(), key=lambda x: x[1], reverse=True))
        self.txt_report.delete("1.0", END)
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tСведения о посещениях сетевых ресурсов.\n")
        self.txt_report.insert(END, f"{self.delimiter}\n")
        self.txt_report.insert(END, "\tРесурс\t\tКоличество посещений\n\n")
        for key, value in counter.items():
            self.txt_report.insert(END, f"{key}\t\t\t\t{value}\n")
        # timer
        # end_time = datetime.datetime.now()
        # f = open('show_stat_site_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_time - start_time}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def show_stat_proto(self):
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        # start_time = datetime.datetime.now()
        connection = connect()
        cursor = connection.cursor()
        cursor.execute("SELECT proto FROM packet")
        rows = cursor.fetchall()
        protocolList = []
        for row in rows:
            protocolList.append(row[0])
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
        # timer
        # end_time = datetime.datetime.now()
        # f = open('show_stat_proto_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_time - start_time}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def show_brief_info(self):
        self.txt_report.configure(state=NORMAL)
        self.figure.clear()
        self.canvas.draw()
        # start_time = datetime.datetime.now()
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
        for row in rows:
            self.txt_report.insert(END, f"No. {row[0]}\n    Time: {row[1]}\n    Length: {row[2]}\n    MAC: {row[3]} → {row[4]}\n    Proto: {row[5]}\n")
            if row[6] and row[7]:
                self.txt_report.insert(END, f"    IP: {row[6]} → {row[7]}\n")
            if row[8] and row[9]:
                self.txt_report.insert(END, f"    Port: {row[8]} → {row[9]}\n")
            if row[10]:
                self.txt_report.insert(END, f"    Info: {row[10]}\n")
            self.txt_report.insert(END, f"{self.delimiter}\n")
        # timer
        # end_time = datetime.datetime.now()
        # f = open('show_brief_info_time.txt', 'a')
        # cursor.execute("SELECT * FROM packet")
        # f.write(f"Rows: {str(cursor.rowcount)} Time: {end_time - start_time}\n")
        # f.close()
        cursor.close()
        connection.close()
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        self.txt_status.insert(END, "Данные обработаны.\n")
        self.running = False
        self.txt_status.configure(state=DISABLED)
        self.txt_report.configure(state=DISABLED)

    def show_info(self):
        messagebox.showinfo("Информация", "Вы работаете с программным компонентом, выполняющим функцию анализа сетевого трафика.\nВыберите в меню Файл->Открыть файл для обработки.\nЕсли в базе уже есть трафик, нажмите кнопку 'Выполнить', чтобы узнать сколько записей содержится в базе.\nЕсли в базе есть данные, выберите в выпадающем списке интересующий Вас вариант анализа.\nНажмите кнопку выполнить.\nРезультат появится в окне 'Отчёт' и 'График'.")