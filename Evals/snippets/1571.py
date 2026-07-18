# prompt_id=1571
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    def add_factory(id, factory):
        JsonObjectFactory.factories[id] = factory

    @staticmethod
    def create(id, data):
        for key in data:
            if key in KEYWORDS:
                new_key = key + "_"
                data[new_key] = data.pop(key)
        if id not in JsonObjectFactory.factories:
            JsonObjectFactory.add_factory(id, eval(id))
        return JsonObjectFactory.factories[id].factory(data)


class JsonObject(object):

    """ This is the base class for all HP SDN Client data types."""

    def __str__(self):
        return self.to_json_string()
