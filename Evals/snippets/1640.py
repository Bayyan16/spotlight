# prompt_id=1640
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def test_missing(self):
        d1 = defaultdict()
        self.assertRaises(KeyError, d1.__missing__, 42)
        d1.default_factory = list
        self.assertEqual(d1.__missing__(42), [])
    
    def test_repr(self):
        d1 = defaultdict()
        self.assertEqual(d1.default_factory, None)
        self.assertEqual(repr(d1), "defaultdict(None, {})")
        self.assertEqual(eval(repr(d1)), d1)
        d1[11] = 41
        self.assertEqual(repr(d1), "defaultdict(None, {11: 41})")
        d2 = defaultdict(int)
        self.assertEqual(d2.default_factory, int)
        d2[12] = 42
        self.assertEqual(repr(d2), "defaultdict(<class 'int'>, {12: 42})")
        def foo(): return 43
        d3 = defaultdict(foo)
        self.assertTrue(d3.default_factory is foo)
