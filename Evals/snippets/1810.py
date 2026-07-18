# prompt_id=1810
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    if started == 1:
        logger.info("bjobs detected job started but not completed: " + str(job))
        return None
    
    #if not found in bjobs, then try bacct (slower than bjobs)
    logger.info("bjobs failed to detect job - trying bacct: " + str(job))
    
    args = ["bacct", "-l", str(job)]
    logger.info("Checking job exit code for job via bacct:" + str(job))
    process = subprocess.Popen(" ".join(args), shell=True, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    for line in process.stdout:
        if line.find("Completed <done>") > -1:
            logger.info("Detected job completed for job: " + str(job))
            return 0
        elif line.find("Completed <exit>") > -1:
            logger.info("Detected job failed for job: " + str(job))
            return 1
    logger.info("Cant determine exit code for job or job still running: " + str(job))
    return None
