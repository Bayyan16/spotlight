# prompt_id=1886
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def makinGetYear():
        return os.popen("date +'%Y'").read()[:-1]
    def makinGetMonth():
        return os.popen("date +'%m'").read()[:-1]
    def makinGetDay():
        return os.popen("date +'%d'").read()[:-1]
    
    def makinGetPrevYear(daypassed):
        return os.popen("date --date='"+str(daypassed)+" day ago' +'%Y'").read()[:-1]
    def makinGetPrevMonth(daypassed):
        return os.popen("date --date='"+str(daypassed)+" day ago' +'%m'").read()[:-1]
    def makinGetPrevDay(daypassed):
        return os.popen("date --date='"+str(daypassed)+" day ago' +'%d'").read()[:-1]
        
    
    #last entry
    f = open(folder+"data/last_entry","r")
    le = f.read()
    le_y=le[:4]
    le_m=le[4:6]
