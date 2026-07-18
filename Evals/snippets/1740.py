# prompt_id=1740
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    #time.sleep(60)
    
    # determine actual NSX portgroup created
    # hack - regex in Python is not a strength
    mob_string = '/mob/?moid=datacenter-2'
    curl_cmd = 'curl -k -u ' + bde_user + ':' + bde_pass + ' ' + prefix + vcm_server + mob_string
    grep_cmd = " | grep -oP '(?<=\(vxw).*(?=" + network + "\))' | grep -oE '[^\(]+$'"
    awk_cmd = " | awk '{print $0 \"" + network + "\"}'"
    full_cmd = curl_cmd + grep_cmd + awk_cmd
    
    p = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, shell=True)
    (net_uid, err) = p.communicate()
    
    # Check to see if network_id is as we expect it
    if 'vxw' in net_uid:
        network_id = net_uid
    else:
        network_id = "vxw" + net_uid
    
    network_id = network_id.rstrip('\n')
