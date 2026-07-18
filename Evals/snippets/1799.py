# prompt_id=1799
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    assert_equal(str(a), '[0 -- 2]')
    assert_equal(repr(a), 'masked_array(data = [0 -- 2],\n'
                          '             mask = [False  True False],\n'
                          '       fill_value = 999999)\n')

def test_pickling(self):
    # Tests pickling
    a = arange(10)
    a[::3] = masked
    a.fill_value = 999
    a_pickled = pickle.loads(a.dumps())
    assert_equal(a_pickled._mask, a._mask)
    assert_equal(a_pickled._data, a._data)
    assert_equal(a_pickled.fill_value, 999)

def test_pickling_subbaseclass(self):
    # Test pickling w/ a subclass of ndarray
    a = array(np.matrix(list(range(10))), mask=[1, 0, 1, 0, 0] * 2)
    a_pickled = pickle.loads(a.dumps())
    assert_equal(a_pickled._mask, a._mask)
