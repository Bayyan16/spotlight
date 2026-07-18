# prompt_id=1719
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    @when('I execute command "{command}" with "{result}"')
    def when_action_command(context, command, result):
        assert command
        context.pre_rpm_packages = get_rpm_package_list()
        assert context.pre_rpm_packages
        context.pre_rpm_packages_version = get_rpm_package_version_list()
        assert context.pre_rpm_packages_version
        context.pre_dnf_packages_version = get_dnf_package_version_list()
        assert context.pre_dnf_packages_version
        cmd_output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        context.cmd_rc = cmd_output.returncode
        if result == "success":
            assert context.cmd_rc == 0
        elif result == "fail":
            assert context.cmd_rc != 0
        else:
            raise AssertionError('The option {} is not allowed option for expected result of command. '
                                 'Allowed options are "success" and "fail"'.format(result))
