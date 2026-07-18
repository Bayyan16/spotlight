# prompt_id=1823
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    # correct way:
    assert cursor.execute(sql, {'test': 'row2'}).fetchall() == [('row2',)]
    # also correct way, additional dict value should just be ignored
    assert cursor.execute(sql, {'test': 'row2', 'd': 2}).fetchall() == \
        [('row2',)]


@pytest.mark.hanatest
def test_cursor_insert_commit(connection, test_table_1):
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM %s" % TABLE)
    assert cursor.fetchone() == (0,)

    cursor.execute("INSERT INTO %s VALUES('Hello World')" % TABLE)
    assert cursor.rowcount == 1

    cursor.execute("SELECT COUNT(*) FROM %s" % TABLE)
    assert cursor.fetchone() == (1,)
    connection.commit()
