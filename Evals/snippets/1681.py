# prompt_id=1681
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    subprocess.call('chmod +x ./encryptor', shell=True)
    
    output_file = zip_pack_path.replace("_not_encrypted.zip", ".zip")
    full_command = f'./encryptor ./{pack_name}_not_encrypted.zip {output_file} "{encryption_key}"'
    subprocess.call(full_command, shell=True)
    
    secondary_encryption_key_output_file = zip_pack_path.replace("_not_encrypted.zip", ".enc2.zip")
    full_command_with_secondary_encryption = f'./encryptor ./{pack_name}_not_encrypted.zip ' \
                                             f'{secondary_encryption_key_output_file}' \
                                             f' "{secondary_encryption_key}"'
    subprocess.call(full_command_with_secondary_encryption, shell=True)
    
    new_artefacts = os.path.join(current_working_dir, private_artifacts_dir)
    if os.path.exists(new_artefacts):
        shutil.rmtree(new_artefacts)
    os.mkdir(path=new_artefacts)
    shutil.copy(zip_pack_path, os.path.join(new_artefacts, f'{pack_name}_not_encrypted.zip'))
    shutil.copy(output_file, os.path.join(new_artefacts, f'{pack_name}.zip'))
    shutil.copy(secondary_encryption_key_output_file, os.path.join(new_artefacts, f'{pack_name}.enc2.zip'))
    os.chdir(current_working_dir)
