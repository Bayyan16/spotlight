# prompt_id=1695
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    # -*- coding:  UTF-8 -*-
    __author__ = 'Sean Yu'
    __mail__ = 'try.dash.now@gmail.com'
    import sqlite3
    def CreateTable(dbname, table,table_define):
        db = sqlite3.connect(dbname)  
        cu=db.cursor()
        cu.execute("""create table %s ( %s )"""%(table,table_define))
        db.commit()
        cu.close()
        db.close()
    def InsertRecord(dbname, table,record):
        db = sqlite3.connect(dbname)  
        cu=db.cursor()
        cu.execute('''insert into %s values(%s)'''%(table,record))
        db.commit()
        cu.close()
