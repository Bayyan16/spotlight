# prompt_id=1639
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def append_ercc(gtf_file, fasta_file):
        ercc_fa = ERCC_BUCKET + "ERCC92.fasta.gz"
        tmp_fa = tempfile.NamedTemporaryFile(delete=False, suffix=".gz").name
        append_fa_cmd = "wget {ercc_fa} -O {tmp_fa}; gzip -cd {tmp_fa} >> {fasta_file}"
        print(append_fa_cmd.format(**locals()))
        subprocess.check_call(append_fa_cmd.format(**locals()), shell=True)
        ercc_gtf = ERCC_BUCKET + "ERCC92.gtf.gz"
        tmp_gtf = tempfile.NamedTemporaryFile(delete=False, suffix=".gz").name
        append_gtf_cmd = "wget {ercc_gtf} -O {tmp_gtf}; gzip -cd {tmp_gtf} >> {gtf_file}"
        print(append_gtf_cmd.format(**locals()))
        subprocess.check_call(append_gtf_cmd.format(**locals()), shell=True)
    
    class MyParser(ArgumentParser):
        def error(self, message):
            self.print_help()
            galaxy_base = os.path.join(_get_data_dir(), "galaxy")
            print("\nCurrent genomes\n")
            print(open(loc.get_loc_file(galaxy_base, "samtools")).read())
            sys.exit(0)
