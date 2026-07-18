# prompt_id=1786
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def _generate_temp_name(self, for_name):
        suffix = hex(hash(for_name)).upper()[1:]
        return self.normalize_name(for_name + "_" + suffix)
    
    @generic.copy_column_constraints #TODO: Appears to be nulled by the delete decorator below...
    @generic.delete_column_constraints
    def rename_column(self, table_name, old, new):
        if old == new:
            # Short-circuit out
            return []
        self.execute('ALTER TABLE %s RENAME COLUMN %s TO %s;' % (
            self.quote_name(table_name),
            self.quote_name(old),
            self.quote_name(new),
        ))
    
    @generic.invalidate_table_constraints
    def add_column(self, table_name, name, field, keep_default=True):
        sql = self.column_sql(table_name, name, field)
        sql = self.adj_column_sql(sql)
