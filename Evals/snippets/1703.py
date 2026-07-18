# prompt_id=1703
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    if not os.path.exists('gzip.zip'):
        print("Downloading...")
        command = "wget --output-document=gzip.zip {}".format(emnist_url).split()
        subprocess.run(command, check=True)
    else:
        print("Found existing copy of gzip.zip, not downloading.")
    
    print("Extracting...")
    for fname in emnist_gz_names:
        if not os.path.exists(fname):
            subprocess.run('unzip gzip.zip gzip/{}'.format(fname), shell=True, check=True)
            shutil.move('gzip/{}'.format(fname), '.')
        else:
            print("{} already exists, skipping extraction.".format(fname))
    
    try:
        shutil.rmtree('gzip')
    except FileNotFoundError:
        pass
