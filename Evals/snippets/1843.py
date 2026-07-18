# prompt_id=1843
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    """
            Setup the DNS in 'node_this' so that 'node_other'
            can be reached by name (e.g., resolved) instead of IP.

            Input:
                    - node_a: Container whose DNS is to be updated.
                    - node_b: Container that should be reachable.
    """
    command = ("docker exec -u root -it {} bash -c \"echo \'{} {}\' >> /etc/hosts\""
               .format(node_this['name'], node_other['ip_addr'], node_other['name']))
    os.popen(command)
    time.sleep(await_seconds)


def number_of_running_processes():
    """
            Return the count of running containers.
    """
    n_docker = common.run_local_cmd('expr $(docker ps -a | wc -l) - 1', get_output=True)
    return int(n_docker)
