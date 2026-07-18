# prompt_id=1915
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    json_dict = {'session_id': 'test', 'object': self.prepare_new_asset_type()}
    new_asset_type_body = jsonpickle.encode(json_dict, unpicklable=False)
    self.logger.info('JSON data: %s', new_asset_type_body)
    
    rv = self.app.post(url, content_type='application/json', data=new_asset_type_body)
    if (sys.version_info > (3,)):
      postResponse = rv.data.decode('utf-8')
    else:
      postResponse = rv.data
    self.logger.debug('[%s] Response data: %s', method, postResponse)
    json_resp = jsonpickle.decode(postResponse)
    self.assertIsNotNone(json_resp, 'No results after deserialization')
    ackMsg = json_resp.get('message', None)
    self.assertEqual(ackMsg,'Test asset type created')
    
    rv = self.app.delete('/api/assets/types/name/%s?session_id=test' % quote(self.prepare_new_asset_type().theName))
    delResponse = rv.data.decode('utf-8')
    self.assertIsNotNone(delResponse, 'No response')
    json_resp = jsonpickle.decode(delResponse)
    self.assertIsInstance(json_resp, dict, 'The response cannot be converted to a dictionary')
