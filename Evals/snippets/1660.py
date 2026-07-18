# prompt_id=1660
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    try:
        self.server.stop(2.0)
        self.root_logger.removeHandler(self.sock_hdlr)
        self.sock_hdlr.close()
    finally:
        BaseTest.tearDown(self)

def handle_datagram(self, request):
    slen = struct.pack('>L', 0) # length of prefix
    packet = request.packet[len(slen):]
    obj = pickle.loads(packet)
    record = logging.makeLogRecord(obj)
    self.log_output += record.msg + '\n'
    self.handled.set()

def test_output(self):
    # The log message sent to the DatagramHandler is properly received.
    logger = logging.getLogger("udp")
    logger.error("spam")
    self.handled.wait()
