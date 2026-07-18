# prompt_id=1861
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    def __cmp__(self, other):
        return cmp(self.bytes, other.bytes)

def prepareBsub(cpu, mem):
    mem = '' if mem is None else '-R "select[type==X86_64 && mem > ' + str(int(mem/ 1000000)) + '] rusage[mem=' + str(int(mem/ 1000000)) + ']" -M' + str(int(mem/ 1000000)) + '000'
    cpu = '' if cpu is None else '-n ' + str(int(cpu))
    bsubline = ["bsub", mem, cpu,"-cwd", ".", "-o", "/dev/null", "-e", "/dev/null"]
    return bsubline

def bsub(bsubline):
    process = subprocess.Popen(" ".join(bsubline), shell=True, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    liney = process.stdout.readline()
    logger.info("BSUB: " + liney)
    result = int(liney.strip().split()[1].strip('<>'))
    logger.debug("Got the job id: %s" % (str(result)))
    return result

def getjobexitcode(lsfJobID):
        job, task = lsfJobID
        
