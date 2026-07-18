# prompt_id=1755
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    os.system(cmdline)
    
    # Add ions
    print("Add ions...")
    cmdline = '\"'+ vmd + '\"' +' -dispdev text -eofexit < '+ tclpath + 'add_ion.tcl' + ' ' + '-args' + ' '+ pdbid +'>> '+ logfile
    os.system(cmdline)
    
    # Calculate grid and center
    print("Calculate center coordinates...")
    cmdline = '\"'+ vmd + '\"' +' -dispdev text -eofexit < '+ tclpath + 'get_center.tcl' + ' ' + '-args' + ' '+ pdbid +'>> '+ logfile
    os.system(cmdline)
    print("Finish!")
    # end main
