# prompt_id=1821
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def is_paired(bam_file):
        """Determine if a BAM file has paired reads.
    
        Works around issues with head closing the samtools pipe using signal trick from:
        http://stackoverflow.com/a/12451083/252589
        """
        bam_file = objectstore.cl_input(bam_file)
        cmd = ("set -o pipefail; "
               "sambamba view -h {bam_file} | head -50000 | "
               "sambamba view -S -F paired /dev/stdin  | head -1 | wc -l")
        p = subprocess.Popen(cmd.format(**locals()), shell=True,
                             executable=do.find_bash(),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL))
        stdout, stderr = p.communicate()
        if p.returncode == 0 or p.returncode == 141 and stderr.strip() == "":
            return int(stdout) > 0
        else:
            raise ValueError("Failed to check paired status of BAM file: %s" % str(stderr))
