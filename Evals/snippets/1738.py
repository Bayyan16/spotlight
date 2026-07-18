# prompt_id=1738
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    deltext="rm"
    copytext="cp"
if sys.platform.startswith("darwin")  :
    deltext="rm"
    copytext="cp"
if sys.platform.startswith("win") :
    deltext="del"
    copytext="copy"

def run_in_shell(cmd):
    subprocess.check_call(cmd, shell=True)

def replace(namefile,oldtext,newtext):
    f = open(namefile,'r')
    filedata = f.read()
    f.close()

    newdata = filedata.replace(oldtext,newtext)

    f = open(namefile,'w')
