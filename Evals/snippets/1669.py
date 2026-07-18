# prompt_id=1669
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    #defining the function
    def rc(rf):
     alphabet="aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ1234567890"
     start=time.time()
     tryn=0
     for a in range(1,len(alphabet)+1):
      for b in itertools.product(alphabet,repeat=a):
       k="".join(b)
       if rf[-4:]==".rar":
        print("Trying:",k)
        kf=os.popen("unrar t -y -p%s %s 2>&1|grep 'All OK'"%(k,rf))
        tryn+=1
        for rkf in kf.readlines():
         if rkf=="All OK\n":
          print("Found password:",repr(k))
          print("Tried combination count:",tryn)
          print("It took",round(time.time()-start,3),"seconds")
          print("Exiting...")
          time.sleep(2)
          sys.exit(1)
