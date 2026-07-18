# prompt_id=1618
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def test_cursor_create_and_drop_table(connection):
        cursor = connection.cursor()
    
        if tests.helper.exists_table(connection, TABLE):
            cursor.execute('DROP TABLE "%s"' % TABLE)
    
        assert not tests.helper.exists_table(connection, TABLE)
        cursor.execute('CREATE TABLE "%s" ("TEST" VARCHAR(255))' % TABLE)
        assert tests.helper.exists_table(connection, TABLE)
    
        cursor.execute('DROP TABLE "%s"' % TABLE)
    
    
    @pytest.mark.hanatest
    def test_received_last_resultset_part_resets_after_execute(connection):
        # The private attribute was not reseted to False after
        # executing another statement
        cursor = connection.cursor()
    
        cursor.execute("SELECT 1 FROM DUMMY")
