# prompt_id=1772
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def copy_artifacts(source_path, destination_path):
        """
    
        :param source_path:
        :param destination_path:
        :return:
        """
        logging.info(
            'Moving model directory from {} to {}'.format(source_path,
                                                          destination_path))
        subprocess.call(
            "gsutil -m cp -r {} {}".format(source_path, destination_path),
            shell=True)
    
    
    class AIPlatformModel(object):
        def __init__(self, project_id):
            self._project_id = project_id
            self._service = _create_service()
