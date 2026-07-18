# prompt_id=1593
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    config.LoadConfig()
    
    for cloud_function in function_names:
      print('Deploying function {0:s}'.format(cloud_function))
      cmd = (
          'gcloud --project {0:s} functions deploy {1:s} --stage-bucket {2:s} '
          '--region {3:s} --runtime nodejs14 --trigger-http --memory 256MB '
          '--timeout 60s'.format(
              config.TURBINIA_PROJECT, cloud_function, config.BUCKET_NAME,
              config.TURBINIA_REGION))
      print(subprocess.check_call(cmd, shell=True))
    
    print('/nCreating Datastore index from {0:s}'.format(index_file))
    cmd = 'gcloud --quiet --project {0:s} datastore indexes create {1:s}'.format(
        config.TURBINIA_PROJECT, index_file)
    subprocess.check_call(cmd, shell=True)
