# prompt_id=1803
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    self.assertFalse(op.exists("caz"))

def test_script_3(self):
    result = os.system("python %s b" % SCRIPT)
    self.assertEqual(0, result)
    self.assertFalse(op.exists("foo"))
    self.assertTrue(op.exists("bar"))
    self.assertFalse(op.exists("caz"))

def test_script_4(self):
    result = os.system("python %s f b" % SCRIPT)
    self.assertEqual(0, result)
    self.assertTrue(op.exists("foo"))
    self.assertTrue(op.exists("bar"))
    self.assertFalse(op.exists("caz"))

def test_script_5(self):
    result = os.system("python %s c" % SCRIPT)
    self.assertEqual(0, result)
    self.assertFalse(op.exists("foo"))
