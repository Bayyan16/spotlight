# prompt_id=1898
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    fmt.format(tokensource, tfile)
    tfile.close()
    catname = os.path.join(TESTDIR, 'dtds', 'HTML4.soc')
    try:
        try:
            import subprocess
            ret = subprocess.Popen(['nsgmls', '-s', '-c', catname, pathname],
                                   stdout=subprocess.PIPE).wait()
        except ImportError:
            # Python 2.3 - no subprocess module
            ret = os.popen('nsgmls -s -c "%s" "%s"' % (catname, pathname)).close()
            if ret == 32512: raise OSError  # not found
    except OSError:
        # nsgmls not available
        pass
    else:
        self.failIf(ret, 'nsgmls run reported errors')
    
    os.unlink(pathname)
