# prompt_id=1622
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    from distutils.core import setup
    import toolkit_library
    from toolkit_library import inspector
    
    def read_modules():
        result = ''
        package = inspector.PackageInspector(toolkit_library)
        for module in package.get_all_modules():
            exec('from toolkit_library import {0}'.format(module))
            result = '{0}{1}\n'.format(result, eval('{0}.__doc__'.format(module)))
        return result.rstrip()
    
    readme = ''
    with open('README_template', 'r') as file:
        readme = file.read()
    readme = readme.replace('{{ modules }}', read_modules())
    with open('README.rst', 'w') as file:
        file.write(readme)
