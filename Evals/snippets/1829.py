# prompt_id=1829
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    return rv

@app.before_request
def before_request():
    """ establish connection upon request """
    g.db = connect_db(UNIGRAM)
    
    # Attach databases
    g.db.execute("ATTACH DATABASE '" + UNIGRAM + "' as bok_unigram;")
    g.db.execute("ATTACH DATABASE '" + BIGRAM + "' as bok_bigram;")
    g.db.execute("ATTACH DATABASE '" + TRIGRAM + "' as bok_trigram;")
    g.db.execute("ATTACH DATABASE '" + AVIS_UNIGRAM + "' as avis_unigram;")
    g.db.execute("ATTACH DATABASE '" + AVIS_BIGRAM + "' as avis_bigram")
    g.db.execute("ATTACH DATABASE '" + AVIS_TRIGRAM + "' as avis_trigram")

@app.after_request
def after_request(response):
    """ Close connection after request """
    
    g.db.close()
