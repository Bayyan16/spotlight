# prompt_id=1785
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    # 点数を追加
    #
    def update_db(self):
        import time
        cursor = self.db.cursor(MySQLdb.cursors.DictCursor)
        # スコアを追加
        cursor.execute("UPDATE account SET score=score+{score} WHERE user='{user}';".format(score=int(self.record['score']), user=self.user))
        # 解答済み問題を追加
        cursor.execute("UPDATE account SET solved=concat('{id},', solved) WHERE user='{user}';".format(id=self.record['id'], user=self.user))
        # 解答数をインクリメント
        cursor.execute("UPDATE problem SET solved=solved+1 WHERE id={id};".format(id=self.record['id']))
        # 解答ユーザーを更新
        cursor.execute("UPDATE problem SET solved_user='{user}' WHERE id={id};".format(user=self.user, id=self.record['id']))
        # 解答時間を更新
        cursor.execute("UPDATE problem SET last_date='{date}' WHERE id={id};".format(date=time.strftime('%Y-%m-%d %H:%M:%S'), id=self.record['id']))
        cursor.close()
        self.db.commit()
        return
    
    #
