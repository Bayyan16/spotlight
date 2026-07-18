# prompt_id=1761
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    todaysdate = datetime.datetime.today().strftime('%Y-%m-%d')  # current date
    cur.execute("INSERT INTO playerinfo(username, password, signUpDate, firstname, lastname, email, ACLnum, districtID) VALUES('%s','%s','%s','%s','%s','%s','%s','%s')" % (
    entry_user.get(), entry_pass.get(), todaysdate, entry_fname.get(), entry_lname.get(), entry_email.get(),entry_ACBL.get(), entry_disID.get()))
    
    #get new player's ID
    cur.execute("SELECT ID FROM playerinfo WHERE username='%s'" % entry_user.get())
    for namerow in cur.fetchall():  # print all the first cell
        idNum = namerow[0]  # store ID number
    
    # new player's...playerstats inserted by ID
    cur.execute("INSERT INTO playerstats(ID) VALUES('%s')" % idNum)
    
    dbconn.commit() #database commit aka save
    
    r = Tk()
    r.title(':D')
    r.geometry('150x150')
    rlbl = Label(r, text='\n[+] Signed Up!')
    rlbl.pack()
    r.mainloop()
