# prompt_id=1798
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    output_file, output_filename = tempfile.mkstemp(dir='.')
    os.close(output_file)
    curl_options = '--header "Accept-Encoding: gzip" --location'
    command = 'curl {} "{}" > {}'.format(curl_options, url, output_filename)
    _progress('downloading gtfs file into: {}'.format(os.path.relpath(output_filename)))
    _execute_command(command)
    return output_filename


def _execute_command(command):
    if os.system(command) != 0:
        raise SystemExit('failed to execute: {}'.format(command))


def _get_modify_date(zip_filename):
    modify_times = _get_modify_times(zip_filename)
    if len(modify_times) > 1:
        _progress_warning('multiple modify times: {}'.format(modify_times))
    return sorted(modify_times)[-1]
