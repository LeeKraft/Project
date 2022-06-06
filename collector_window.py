#!/usr/bin/python3
import subprocess #nosec
import datetime
import re
import glob
from threading import Thread
from tkinter import Tk, END, NORMAL, WORD, DISABLED, SUNKEN, Menu, LabelFrame, Label, Button, messagebox, Frame, IntVar, Radiobutton, Entry
from tkinter.ttk import Combobox
from tkinter.scrolledtext import ScrolledText

from analyze_window import AnalyzeWindow

class CollectorWindow:
    protocols = ['all','arp','rarp','tcp','udp','ip','ip6','icmp','icmp6']
    bg_color = "#e4eff2"
    bg_middle = "#c7d3d6"
    running = False
    def __init__(self):
        """Sets all the necessary attributes for an object of the CollectorWindow class"""
        self.root = Tk()
        self.root.title("Сбор трафика")
        self.root.geometry('{}x{}+{}+{}'.format(600, 500, self.root.winfo_screenwidth()//2 - 300, self.root.winfo_screenheight()//2 - 250))
        self.root.resizable(False,False)
        # menu
        mainmenu = Menu(self.root)
        self.root.configure(menu=mainmenu)
        helpmenu = Menu(mainmenu, tearoff=0)
        helpmenu.add_command(label="Узнать мой IP", command=self.show_ip)
        helpmenu.add_command(label="О программе", command=self.show_info)
        mainmenu.add_cascade(label="Помощь", menu=helpmenu)
        # frame
        self.frm_top = LabelFrame(master=self.root, width=600, height=320, relief=SUNKEN, borderwidth=5, bg=self.bg_color, font=("Arial",12, "bold"), text="Параметры")
        self.frm_middle = Frame(master=self.root, width=600, height=50, relief=SUNKEN, borderwidth=5, bg=self.bg_middle)
        self.frm_bottom = LabelFrame(master=self.root, width=600, height=130, relief=SUNKEN, borderwidth=5, bg=self.bg_color, font=("Arial",12, "bold"), text="Статус")
        # label
        self.lbl_inter = Label(master=self.frm_top, text="Интерфейс", font=("Arial",14), bg=self.bg_color)
        self.lbl_inter.place(relx=0.07, rely=0.07)
        self.lbl_host = Label(master=self.frm_top, text="IP адрес", font=("Arial",14), bg=self.bg_color)
        self.lbl_host.place(relx=0.07, rely=0.19)
        self.lbl_port = Label(master=self.frm_top, text="Порт", font=("Arial",13), bg=self.bg_color)
        self.lbl_port.place(relx=0.71, rely=0.19)
        self.lbl_src = Label(master=self.frm_top, text="IP адрес источника", font=("Arial",14), bg=self.bg_color)
        self.lbl_src.place(relx=0.07, rely=0.31)
        self.lbl_src_port = Label(master=self.frm_top, text="Порт", font=("Arial",14), bg=self.bg_color)
        self.lbl_src_port.place(relx=0.71, rely=0.31)
        self.lbl_dst = Label(master=self.frm_top, text="IP адрес назначения", font=("Arial",14), bg=self.bg_color)
        self.lbl_dst.place(relx=0.07, rely=0.43)
        self.lbl_dst_port = Label(master=self.frm_top, text="Порт", font=("Arial",14), bg=self.bg_color)
        self.lbl_dst_port.place(relx=0.71, rely=0.43)
        self.lbl_proto = Label(master=self.frm_top, text="Протокол", font=("Arial",14), bg=self.bg_color)
        self.lbl_proto.place(relx=0.07, rely=0.55)
        self.lbl_time = Label(master=self.frm_top, text="Время сбора пакетов", font=("Arial",14), bg=self.bg_color)
        self.lbl_time.place(relx=0.07, rely=0.67)
        self.lbl_time_unit = Label(master=self.frm_top, text="(s/m/h/d)", font=("Arial",14), bg=self.bg_color)
        self.lbl_time_unit.place(relx=0.7, rely=0.67)
        self.lbl_count = Label(master=self.frm_top, text="Количество пакетов", font=("Arial",14), bg=self.bg_color)
        self.lbl_count.place(relx=0.07, rely=0.79)
        # radiobutton
        self.choice_addr = IntVar(value=0)
        self.choice_time_count = IntVar(value=0)
        self.rbtn_host = Radiobutton(master=self.frm_top, variable=self.choice_addr, value=0, bg=self.bg_color, activebackground=self.bg_middle, command=self.change_host)
        self.rbtn_host.place(relx=0.01, rely=0.19)
        self.rbtn_src_dst = Radiobutton(master=self.frm_top, variable=self.choice_addr, value=1, bg=self.bg_color, activebackground=self.bg_middle, command=self.change_host)
        self.rbtn_src_dst.place(relx=0.01, rely=0.31)
        self.rbtn_time = Radiobutton(master=self.frm_top, variable=self.choice_time_count, value=0, bg=self.bg_color, activebackground=self.bg_middle, command=self.change_mode)
        self.rbtn_time.place(relx=0.01, rely=0.67)
        self.rbtn_count = Radiobutton(master=self.frm_top, variable=self.choice_time_count, value=1, bg=self.bg_color, activebackground=self.bg_middle, command=self.change_mode)
        self.rbtn_count.place(relx=0.01, rely=0.79)
        # combo and entry
        self.cmb_inter = Combobox(master=self.frm_top, width=15, font=("Arial",14), values=self.get_interfaces(), state="readonly")
        self.cmb_inter.set("any")
        self.cmb_inter.place(relx=0.4, rely=0.07)
        self.ent_host = Entry(master=self.frm_top, width=18)
        self.ent_host.place(relx=0.4, rely=0.19)
        self.ent_port = Entry(master=self.frm_top, width=10)
        self.ent_port.place(relx=0.81, rely=0.19)
        self.ent_src = Entry(master=self.frm_top, width=18, state=DISABLED)
        self.ent_src.place(relx=0.4, rely=0.31)
        self.ent_src_port = Entry(master=self.frm_top, width=10, state=DISABLED)
        self.ent_src_port.place(relx=0.81, rely=0.31)
        self.ent_dst = Entry(master=self.frm_top, width=18, state=DISABLED)
        self.ent_dst.place(relx=0.4, rely=0.43)
        self.ent_dst_port = Entry(master=self.frm_top, width=10, state=DISABLED)
        self.ent_dst_port.place(relx=0.81, rely=0.43)
        self.cmb_proto = Combobox(master=self.frm_top, width=15, font=("Arial",14), values=self.protocols, state="readonly")
        self.cmb_proto.set("all")
        self.cmb_proto.place(relx=0.4, rely=0.55)
        self.ent_time = Entry(master=self.frm_top, width=18)
        self.ent_time.place(relx=0.4, rely=0.67)
        self.ent_count = Entry(master=self.frm_top, width=18, state=DISABLED)
        self.ent_count.place(relx=0.4, rely=0.79)
        self.txt_status = ScrolledText(master=self.frm_bottom, width=64, height=4.5, wrap=WORD, font=("Arial",12), state=DISABLED)
        self.txt_status.place(relx=0, rely=0.01)
        # button
        self.btn_start = Button(master=self.frm_middle, width=10, text="Старт", font=("Arial",14), command=self.start)
        self.btn_start.place(relx=0.03, rely=0.06)
        self.btn_stop = Button(master=self.frm_middle, width=10, text="Стоп", font=("Arial",14), command=self.stop)
        self.btn_stop.place(relx=0.27, rely=0.06)
        self.btn_analyze = Button(master=self.frm_middle, width=10, text="Анализ", font=("Arial",14), command=self.analyze_window)
        self.btn_analyze.place(relx=0.75, rely=0.06)
        self.frm_top.place(x=0, y=0)
        self.frm_middle.place(x=0, y=320)
        self.frm_bottom.place(x=0, y=370)

    def run(self):
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        self.root.mainloop()

    def on_close(self):
        self.stop()
        self.root.destroy()

    def show_ip(self):
        try:
            ip = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if not ip.returncode:
                messagebox.showinfo("Информация", f"Ваш IP адрес: \n{ip.stdout.split()[0]}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось узнать IP адрес.\nПрограмма выдала исключение: {str(e)}")

    def show_info(self):
        messagebox.showinfo("Информация", "Вы работаете с программным компонентом, выполняющим функцию сбора сетевого трафика.\nВведите необходимые фильтры для собираемого трафика, либо оставьте поля пустыми.\nЧтобы начать сбор, нажмите кнопку 'Старт'.\nЧтобы остановить - кнопку 'Стоп'.\nЧтобы перейти в программный компонент, реализующий анализ трафика, нажмите кнопку 'Анализ'.")
    
    def get_interfaces(self) -> list:
        lst_interfaces = list()
        try:
            interfaces = subprocess.run(['ls','/sys/class/net'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if not interfaces.returncode:
                lst_interfaces = interfaces.stdout.split()
                lst_interfaces.append("any")
                return lst_interfaces
            else:
                messagebox.showerror("Ошибка", f"Не удалось получить список доступных интерфейсов.\nПрограмма выдала ошибку: {interfaces.stderr}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось получить список доступных интерфейсов.\nПрограмма выдала исключение: {str(e)}")

    def run_tcpdump(self, command: list):
        self.txt_status.configure(state=NORMAL)
        self.txt_status.insert(END, "Идёт сбор пакетов...\n")
        try:
            tcpdump = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            self.txt_status.delete("1.0", END)
            if tcpdump.returncode in [0,124]:
                self.txt_status.configure(state=NORMAL)
                self.txt_status.insert(END, "Сбор пакетов успешно завершен.\nСозданы файлы, содержащие собранный трафик:\n")
                for filename in glob.glob(f"{command[-1]}*"):
                    self.txt_status.insert(END, filename[5:])
            else:
                self.txt_status.insert(END, f"Ошибка сбора пакетов. Код ошибки: {tcpdump.returncode}\n")
        except Exception as e:
            print(e)
            self.txt_status.insert(END, str(e))
        self.txt_status.configure(state=DISABLED)
        self.running = False

    def change_host(self):
        if self.choice_addr.get() == 0:
            self.ent_host.configure(state=NORMAL)
            self.ent_port.configure(state=NORMAL)
            self.ent_src.configure(state=DISABLED)
            self.ent_src_port.configure(state=DISABLED)
            self.ent_dst.configure(state=DISABLED)
            self.ent_dst_port.configure(state=DISABLED)
        else:
            self.ent_host.configure(state=DISABLED)
            self.ent_port.configure(state=DISABLED)
            self.ent_src.configure(state=NORMAL)
            self.ent_src_port.configure(state=NORMAL)
            self.ent_dst.configure(state=NORMAL)
            self.ent_dst_port.configure(state=NORMAL)
    
    def change_mode(self):
        if self.choice_time_count.get() == 0:
            self.ent_time.configure(state=NORMAL)
            self.ent_count.configure(state=DISABLED)
        else:
            self.ent_time.configure(state=DISABLED)
            self.ent_count.configure(state=NORMAL)

    def start(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        if self.running:
            self.txt_status.insert(END, "Сбор пакетов уже запущен.\nИдёт сбор пакетов...\n")
            self.txt_status.configure(state=DISABLED)
            return
        infinite = False
        parametrs = dict.fromkeys(['interface', 'host', 'port', 'src', 'src_port', 'dst', 'dst_port', 'proto', 'time', 'count'])
        if self.choice_time_count.get() == 0 and len(self.ent_time.get()):
            # ent_time
            temp = self.ent_time.get().replace(" ", "")
            if re.match(r'^(\d)+[a-zA-Z]*$', temp):
                temp = str(int(''.join([str(i) for i in temp if i.isdigit()]))) + ''.join([str(i) for i in temp if not i.isdigit()])
                self.ent_time.delete(0, END)
                self.ent_time.insert(0, temp)
            else:
                self.ent_time.delete(0, END)
                self.ent_time.insert(0, temp)
            if re.match(r'^(\s)*\d{1,5}(s|m|h|d)(\s)*$', self.ent_time.get()):
                parametrs['time'] = self.ent_time.get()
                self.txt_status.insert(END, f"Установлено время сбора пакетов: {parametrs['time']}.\n")
            elif len(self.ent_time.get()):
                self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_time['text'])}\".\nМаксимальное количество цифр 5.\nПример формата времени: 50000s.\n")
                self.txt_status.configure(state=DISABLED)
                return
        elif self.choice_time_count.get() == 1 and len(self.ent_count.get()):
            # ent_count
            temp = self.ent_count.get().replace(" ", "")
            if temp.isdecimal():
                self.ent_count.delete(0, END)
                self.ent_count.insert(0, str(int(temp)))
            else:
                self.ent_count.delete(0, END)
                self.ent_count.insert(0, temp)
            if re.match(r'^(\s)*\d{1,12}(\s)*$', self.ent_count.get()) and int(self.ent_count.get()) in range(pow(10, 11) + 1):
                parametrs['count'] = self.ent_count.get()
                self.txt_status.insert(END, f"Установлено ограничение по количеству собираемых пакетов: {parametrs['count']}.\n")
            elif len(self.ent_count.get()):
                self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_count['text'])}\".\nКоличество пакетов должно быть положительным числом, не превышающим 100 млрд.\n")
                self.txt_status.configure(state=DISABLED)
                return
        else:
            infinite=True
            
        # cmb_inter
        parametrs['interface'] = self.cmb_inter.get()
        if parametrs['interface'] != "any":
            self.txt_status.insert(END, f"Выбран интерфейс: {parametrs['interface']}.\n")
        else:
            self.txt_status.insert(END, "Интерфейс не задан.\n")
        if self.choice_addr.get() == 0:
            if len(self.ent_host.get()):
                # ent_host
                temp = self.ent_host.get().replace(" ", "")
                temp_lst = self.ent_host.get().split('.')
                if all(i.isdecimal() for i in temp_lst):
                    self.ent_host.delete(0, END)
                    temp_lst = list(map(int, temp_lst))
                    self.ent_host.insert(0, ".".join([str(i) for i in temp_lst]))
                else:
                    self.ent_host.delete(0, END)
                    self.ent_host.insert(0, ".".join(temp_lst))
                if re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', self.ent_host.get()) and all(int(i) in range(256) for i in self.ent_host.get().split('.')):
                    parametrs['host'] = self.ent_host.get()
                    self.txt_status.insert(END, f"Установлено значение IP адреса: {parametrs['host']}.\n")
                elif self.ent_host.get().isspace() == False and len(self.ent_host.get()):
                    self.txt_status.insert(END, f"Ошибка формата в поле \"{str(self.lbl_host['text'])}\".\nБайты адреса должны быть от 0 до 255 включительно.\nПример IP адреса - 192.168.1.254\n")
                    self.txt_status.configure(state=DISABLED)
                    return
            if len(self.ent_port.get()):
                # ent_port
                temp = self.ent_port.get().replace(" ", "")
                if temp.isdecimal():
                    self.ent_port.delete(0, END)
                    self.ent_port.insert(0, str(int(temp)))
                else:
                    self.ent_port.delete(0, END)
                    self.ent_port.insert(0, temp)
                if not self.ent_port.get().isdecimal() and not self.ent_port.get().isspace() and len(self.ent_port.get()):
                    self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_port['text'])}\".\nНомер порта должен быть задан десятичным неотрицательным числом.\n")
                    self.txt_status.configure(state=DISABLED)
                    return
                if re.match(r'^\d{1,5}$', self.ent_port.get()) and int(self.ent_port.get()) in range(65536):
                    parametrs['port'] = self.ent_port.get()
                    self.txt_status.insert(END, f"Установлено значение порта: {parametrs['port']}.\n")
                elif not self.ent_port.get().isspace() and len(self.ent_port.get()):
                    self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_port['text'])}\".\nНомер порта лежит в диапазоне от 0 до 65535.\n")
                    self.txt_status.configure(state=DISABLED)
                    return
        else:
            if len(self.ent_src.get()):
                # ent_src
                temp = self.ent_src.get().replace(" ", "")
                temp_lst = self.ent_src.get().split('.')
                if all(i.isdecimal() for i in temp_lst):
                    self.ent_src.delete(0, END)
                    temp_lst = list(map(int, temp_lst))
                    self.ent_src.insert(0, ".".join([str(i) for i in temp_lst]))
                else:
                    self.ent_src.delete(0, END)
                    self.ent_src.insert(0, ".".join(temp_lst))
                if re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', self.ent_src.get()) and all(int(i) in range(256) for i in self.ent_src.get().split('.')):
                    parametrs['src'] = self.ent_src.get()
                    self.txt_status.insert(END, f"Установлено значение IP адреса источника: {parametrs['src']}.\n")
                elif self.ent_src.get().isspace() == False and len(self.ent_src.get()):
                    self.txt_status.insert(END, f"Ошибка формата в поле \"{str(self.lbl_src['text'])}\".\nБайты адреса должны быть от 0 до 255 включительно.\nПример IP адреса - 192.168.1.254\n")
                    self.txt_status.configure(state=DISABLED)
                    return
            if len(self.ent_src_port.get()):
                # ent_src_port
                temp = self.ent_src_port.get().replace(" ", "")
                if temp.isdecimal():
                    self.ent_src_port.delete(0, END)
                    self.ent_src_port.insert(0, str(int(temp)))
                else:
                    self.ent_src_port.delete(0, END)
                    self.ent_src_port.insert(0, temp)
                if not self.ent_src_port.get().isdecimal() and not self.ent_src_port.get().isspace() and len(self.ent_src_port.get()):
                    self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_src_port['text'])}\".\nНомер порта должен быть задан десятичным неотрицательным числом.\n")
                    self.txt_status.configure(state=DISABLED)
                    return
                if re.match(r'^\d{1,5}$', self.ent_src_port.get()) and int(self.ent_src_port.get()) in range(65536):
                    parametrs['src_port'] = self.ent_src_port.get()
                    self.txt_status.insert(END, f"Установлено значение порта источника: {parametrs['src_port']}.\n")
                elif not self.ent_src_port.get().isspace() and len(self.ent_src_port.get()):
                    self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_src_port['text'])}\".\nНомер порта лежит в диапазоне от 0 до 65535.\n")
                    self.txt_status.configure(state=DISABLED)
                    return
            if len(self.ent_dst.get()):
                # ent_dst
                temp = self.ent_dst.get().replace(" ", "")
                temp_lst = self.ent_dst.get().split('.')
                if all(i.isdecimal() for i in temp_lst):
                    self.ent_dst.delete(0, END)
                    temp_lst = list(map(int, temp_lst))
                    self.ent_dst.insert(0, ".".join([str(i) for i in temp_lst]))
                else:
                    self.ent_dst.delete(0, END)
                    self.ent_dst.insert(0, ".".join(temp_lst))
                if re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', self.ent_dst.get()) and all(int(i) in range(256) for i in self.ent_dst.get().split('.')):
                    parametrs['dst'] = self.ent_dst.get()
                    self.txt_status.insert(END, f"Установлено значение IP адреса назначения: {parametrs['dst']}.\n")
                elif self.ent_dst.get().isspace() == False and len(self.ent_dst.get()):
                    self.txt_status.insert(END, f"Ошибка формата в поле \"{str(self.lbl_dst['text'])}\".\nБайты адреса должны быть от 0 до 255 включительно.\nПример IP адреса - 192.168.1.254\n")
                    self.txt_status.configure(state=DISABLED)
                    return
            if len(self.ent_dst_port.get()):
                # ent_dst_port
                temp = self.ent_dst_port.get().replace(" ", "")
                if temp.isdecimal():
                    self.ent_dst_port.delete(0, END)
                    self.ent_dst_port.insert(0, str(int(temp)))
                else:
                    self.ent_dst_port.delete(0, END)
                    self.ent_dst_port.insert(0, temp)
                if not self.ent_dst_port.get().isdecimal() and not self.ent_dst_port.get().isspace() and len(self.ent_dst_port.get()):
                    self.txt_status.insert(END, "Ошибка в поле \"" + str(self.lbl_dst_port['text'] + "\".\nНомер порта должен быть задан десятичным неотрицательным числом.\n"))
                    self.txt_status.configure(state=DISABLED)
                    return
                if re.match(r'^\d{1,5}$', self.ent_dst_port.get()) and int(self.ent_dst_port.get()) in range(65536):
                    parametrs['dst_port'] = self.ent_dst_port.get()
                    self.txt_status.insert(END, f"Установлено значение порта назначения: {parametrs['dst_port']}.\n")
                elif not self.ent_dst_port.get().isspace() and len(self.ent_dst_port.get()):
                    self.txt_status.insert(END, f"Ошибка в поле \"{str(self.lbl_dst_port['text'])}\".\nНомер порта лежит в диапазоне от 0 до 65535.\n")
                    self.txt_status.configure(state=DISABLED)
                    return
        # cmb_proto
        parametrs['proto'] = self.cmb_proto.get()
        if parametrs['proto'] != "all":
            self.txt_status.insert(END, f"Выбран протокол: {parametrs['proto']}.\n")
        else:
            self.txt_status.insert(END, "Протокол не задан.\n")

        filename = "dump/" + datetime.datetime.now().strftime('%d-%b-%Y_%H:%M:%S') + "_dump.pcap"
        command = ['tcpdump']
        if parametrs['interface'] != "any":
            command.extend(['-i', parametrs['interface']])
        if parametrs['proto'] != "all" and (parametrs['host'] != None or parametrs['port'] != None or parametrs['src'] != None or parametrs['src_port'] != None or parametrs['dst'] != None or parametrs['dst_port'] != None):
            command.extend([parametrs['proto'], 'and'])
        elif parametrs['proto'] != "all":
            command.extend([parametrs['proto']])
        if parametrs['host'] != None:
            command.extend(['host', parametrs['host']])
        if parametrs['host'] != None and parametrs['port'] != None:
            command.extend(['and', 'port', parametrs['port']])
        elif parametrs['port'] != None:
            command.extend(['port', parametrs['port']])

        if parametrs['src'] != None:
            command.extend(['src', parametrs['src']])
        if parametrs['src'] != None and parametrs['src_port'] != None:
            command.extend(['and', 'src', 'port', parametrs['src_port']])
        elif parametrs['src_port'] != None:
            command.extend(['src', 'port', parametrs['src_port']])
        if (parametrs['src'] != None or parametrs['src_port'] != None) and parametrs['dst'] != None:
            command.extend(['and', 'dst', parametrs['dst']])
        elif parametrs['dst'] != None:
            command.extend(['dst', parametrs['dst']])
        if (parametrs['src'] != None or parametrs['src_port'] != None or parametrs['dst'] != None) and parametrs['dst_port'] != None:
            command.extend(['and', 'dst', 'port', parametrs['dst_port']])
        elif parametrs['dst_port'] != None:
            command.extend(['dst', 'port', parametrs['dst_port']])

        if infinite:
            command.extend(['-C', '1000', '-Z', 'root', '-w', filename, ])
        elif parametrs['time'] != None:
            command = ['timeout', parametrs['time']] + command
            command.extend(['-w', filename])
        else:
            command.extend(['-c', parametrs['count'], '-w', filename])
        self.txt_status.configure(state=DISABLED)
        self.running = True
        thread = Thread(target=self.run_tcpdump, args=(command,), daemon=True)
        thread.start()

    def stop(self):
        self.txt_status.configure(state=NORMAL)
        self.txt_status.delete("1.0", END)
        try:
            self.txt_status.insert(END, "Остановка сбора пакетов...\n")
            proc_id: str
            pidof = subprocess.run(['pidof', 'tcpdump'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
            if not pidof.returncode:
                proc_id = pidof.stdout.strip()
                if len(proc_id):
                    kill = subprocess.run(['kill', proc_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
                    if not kill.returncode:
                        self.txt_status.insert(END, "Сбор пакетов остановлен.\n")
                    else:
                        self.txt_status.insert(END, f"Ошибка остановки сбора пакетов. Код ошибки: {kill.returncode}.\n")
            elif pidof.returncode == 1:
                self.txt_status.insert(END, "Процесс сбора пакетов не был запущен.\n")
        except Exception as e:
            self.txt_status.insert(END, str(e))
        self.txt_status.configure(state=DISABLED)
        self.running = False

    def analyze_window(self):
        self.analyze_window = AnalyzeWindow(self.root)
    
