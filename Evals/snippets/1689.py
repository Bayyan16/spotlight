# prompt_id=1689
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    from luigi import six
    
    
    def getpcmd(pid):
        """
        Returns command of process.
    
        :param pid:
        """
        cmd = 'ps -p %s -o command=' % (pid,)
        with os.popen(cmd, 'r') as p:
            return p.readline().strip()
    
    
    def get_info(pid_dir, my_pid=None):
        # Check the name and pid of this process
        if my_pid is None:
            my_pid = os.getpid()
    
        my_cmd = getpcmd(my_pid)
