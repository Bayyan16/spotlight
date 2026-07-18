# prompt_id=1700
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def exception(self, level, source, objid, text):
        ''' Generate an Exception Message
        '''
        vals = (objid, str(self.sessionid), level, source, time.ctime(), text)
        types = ("NODE", "SESSION", "LEVEL", "SOURCE", "DATE", "TEXT")
        tlvdata = ""
        for (t,v) in zip(types, vals):
            if v is not None:
                tlvdata += coreapi.CoreExceptionTlv.pack(
                                    eval("coreapi.CORE_TLV_EXCP_%s" % t), v)
        msg = coreapi.CoreExceptionMessage.pack(0, tlvdata)
        self.warn("exception: %s (%s) %s" % (source, objid, text))
        # send Exception Message to connected handlers (e.g. GUI)
        self.broadcastraw(None, msg)
    
    def getcfgitem(self, cfgname):
        ''' Return an entry from the configuration dictionary that comes from
            command-line arguments and/or the core.conf config file.
        '''
