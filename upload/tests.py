import MySQLdb
import time
import sys
import requests

s = requests.post()
s.

def create_temp_db():

    conn = MySQLdb.connect(host='127.0.0.1', port=3306, user='root', passwd='dviis518', db="ADIDAS")
    cur = conn.cursor()
    # database name can be crashed
    sql = """SELECT id, name, rva, bytes_hash FROM upload_arm_functions WHERE name = '__fxstatat64'"""
    cur.execute(sql)
    rows = cur.fetchall()
    print(rows)


create_temp_db()
