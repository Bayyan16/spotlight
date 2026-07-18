# prompt_id=1578
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    poiss = stats.poisson(3.)
    sample = stats.rv_discrete(values=([0, 1, 2, 3],
                                       [0.1, 0.2, 0.3, 0.4]))
    
    for distfn in [beta, poiss, sample]:
        distfn.random_state = 1234
        distfn.rvs(size=8)
        s = pickle.dumps(distfn)
        r0 = distfn.rvs(size=8)
    
        unpickled = pickle.loads(s)
        r1 = unpickled.rvs(size=8)
        assert_equal(r0, r1)
    
        # also smoke test some methods
        medians = [distfn.ppf(0.5), unpickled.ppf(0.5)]
        assert_equal(medians[0], medians[1])
        assert_equal(distfn.cdf(medians[0]),
                     unpickled.cdf(medians[1]))
