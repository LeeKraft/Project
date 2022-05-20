#!/usr/bin/python3
import psycopg2

def connect():
  connection = psycopg2.connect(
    database="networktraffic",
    user="larry",
    password="larry",
    host="localhost",
    port="5432"
  )
  return connection

def create_table(connection):
  cursor = connection.cursor()
  cursor.execute('''DROP table IF EXISTS packet ''')
  cursor.execute('''CREATE TABLE packet  
       (ID SERIAL PRIMARY KEY,
       Time CHAR(32),
       Length INTEGER,
       SrcMac CHAR(17),
       DstMac CHAR(17),
       Proto CHAR(16),
       SrcIP CHAR(64),
       DstIP CHAR(64),
       SrcPort INTEGER,
       DstPort INTEGER,
       Info TEXT);''')
  connection.commit()
  cursor.close()

def put_data(connection, time, length, srcMac, dstMac, proto, srcIP, dstIP, srcPort, dstPort, info):
  cursor = connection.cursor()
  query = ''' INSERT INTO PACKET (Time,Length,SrcMac,DstMac,Proto,SrcIP,DstIP,SrcPort,DstPort,Info) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'''
  record = (time, length, srcMac, dstMac, proto, srcIP, dstIP, srcPort, dstPort, info)
  cursor.execute(query, record)
  connection.commit()
  cursor.close()

