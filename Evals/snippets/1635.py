# prompt_id=1635
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    cu=db.cursor()
    cu.execute('''delete from %s where %s'''%(table,condition))
    db.commit()
    cu.close()
    db.close()   
def FetchRecord(dbname,table, condition=''):
    db = sqlite3.connect(dbname)  
    cu=db.cursor()
    if condition!='':
        condition="where %s"%condition
    records =cu.execute('''select * from %s %s'''%(table,condition))
    result =[]    
    for i in records:
        i= list(i)
        result.append(i)
     
    db.commit()
    cu.close()
    db.close()   
    return result
