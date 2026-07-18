# prompt_id=1662
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@DB stuff@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    #entry_user.get() //username
    var = dbConnect()
    dbconn = mysql.connect(host=var.host, user=var.user, password=var.password, db=var.db)
    cur = dbconn.cursor()  # Cursor object - required to execute all queries
    global data
    data=[]
    
    # get all info from playerinfo and playerstats using current username
    cur.execute(
        "SELECT playerinfo.firstname, playerinfo.lastname, playerinfo.username, playerinfo.email, playerinfo.signUpDate, playerinfo.districtID, playerinfo.ACLnum, playerstats.dealsplayed, playerstats.level, playerstats.exp, playerstats.coins, playerstats.tournys FROM playerstats INNER JOIN playerinfo ON playerinfo.ID=playerstats.ID AND playerinfo.username='%s'" % entry_user.get())
    for namerow in cur.fetchall():  # print all info
        fn = namerow[0]  # firstname
        ln = namerow[1]  # lastname
        un = namerow[2] #username
        em = namerow[3]  # email
        sData = namerow[4] # signUpDate
        districtID = namerow[5] # District ID
        acblNumba = namerow[6] # ACBL Number
