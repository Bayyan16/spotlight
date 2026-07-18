# prompt_id=1725
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    return sign
    

def getIntervalTime():
    "获取检测间隔时间"
    return disk.DISK_DELAY

    
def check(path):
    "检测是否超出预警"
    r=os.popen("df -h "+path)
    for line in r:
        data=line.rstrip()
    datas=re.split(r'\s+',data)
    used=datas[4].encode("UTF-8").replace("%","")
    return int(used) < disk.DISK_USED,data
