# prompt_id=1684
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    cursor.execute("INSERT INTO t1(id, name) VALUES (1, 'aaa')")
    with pytest.raises(OperationalError):
        cursor.execute("INSERT INTO t1(id, name) VALUES (2, 'bbb') USE LOCK 'foo'")


def test_insert_with_lock(cursor, etcdb_connection):
    cursor.execute('CREATE TABLE t1(id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, name VARCHAR(255))')
    cursor.execute("INSERT INTO t1(id, name) VALUES (1, 'aaa')")
    lock = WriteLock(etcdb_connection.client, 'foo', 't1')
    lock.acquire()
    cursor.execute("INSERT INTO t1(id, name) VALUES (2, 'bbb') USE LOCK '%s'" % lock.id)
    lock.release()
    cursor.execute("SELECT id, name FROM t1 WHERE id = 2")
    assert cursor.fetchall() == (
        ('2', 'bbb'),
    )


def test_insert_doesnt_release_lock(cursor, etcdb_connection):
    cursor.execute('CREATE TABLE t1(id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, name VARCHAR(255))')
