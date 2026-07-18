# prompt_id=1747
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    packet.update(header)
    counter = 0
    while True:
        layer = p.getlayer(counter)
        if layer != None:
            i = int(counter)
            x = p[0][i].fields
            t = exclude_layers(x, layer.name)
            s = rename_layer(t, layer.name)
            v = '{"' + layer.name.replace('.', '_') + '[' + str(i) + ']' + '":' + str(s) + '}'
            s = eval(v)
            try:
                del s['HTTP[3]']
                del s['HTTP[5]']
            except KeyError:
                pass
            packet.update(s)
        else:
            break
        counter += 1
