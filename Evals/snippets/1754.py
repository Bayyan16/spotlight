# prompt_id=1754
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    raise ValueError('Stop time needs to be specified')

#~ tmpdict = copy.deepcopy(kwargs)
#~ print self.dic_vars

routine_up = self.dic_vars['surface_upward_flux']
routine_down = self.dic_vars['sis']

#sw_down = self.get_surface_shortwave_radiation_down(interval=interval, **kwargs)
cmd = 'sw_down = self.' + routine_down
exec(cmd)

#sw_up = self.get_surface_shortwave_radiation_up(interval=interval, **kwargs)
cmd = 'sw_up = self.' + routine_up
exec(cmd)

# climatological mean
alb = sw_up[0].div(sw_down[0])
alb.label = self.experiment + ' albedo'
alb.unit = '-'
