# prompt_id=1816
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    @task
    def test():
        os.system('coverage run --source tryagain -m py.test')
        os.system('coverage report')
    
    
    @task
    def register(production=False):
        target = 'pypi' if production else 'pypitest'
        os.system('python3 setup.py register -r %s' % target)
    
    
    @task
    def upload(production=False):
        target = 'pypi' if production else 'pypitest'
        os.system('python3 setup.py bdist_wheel upload -r %s' % target)
