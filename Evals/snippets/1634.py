# prompt_id=1634
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    self.assertFalse(op.exists("caz"))

def test_script_5(self):
    result = os.system("python %s c" % SCRIPT)
    self.assertEqual(0, result)
    self.assertFalse(op.exists("foo"))
    self.assertFalse(op.exists("bar"))
    self.assertTrue(op.exists("caz"))

def test_script_6(self):
    result = os.system("python %s c f" % SCRIPT)
    self.assertEqual(0, result)
    self.assertTrue(op.exists("foo"))
    self.assertFalse(op.exists("bar"))
    self.assertTrue(op.exists("caz"))

def test_script_7(self):
    result = os.system("python %s -d" % SCRIPT)
    self.assertEqual(0, result)
    self.assertFalse(op.exists("foo"))
