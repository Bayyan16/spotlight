# prompt_id=1749
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    os.remove(tmp_bam_filename)
    # rename sorted bam to output bam filename
    os.rename(data_dir + "/tmp.sort.bam", bam_filename)

    
def read_bam(bam):
    """
    Read a bam file into a list where each element of the list is a line from
    the bam file (with the newline stripped). The header is discarded.
    """
    res = subprocess.check_output('samtools view %s' % bam, shell=True)
    return res.strip().split('\n')


def test_filter_remapped_reads_pe():
    test_dir = "test_data"
    to_remap_bam_filename = "test_data/test.to.remap.bam"
    remap_bam_filename = "test_data/test.remap.bam"
    keep_bam_filename = "test_data/keep.bam"
