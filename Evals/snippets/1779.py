# prompt_id=1779
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def update_result(self, context):
        if self.use_tmpfs:
            on_device_tarball = self.device.path.join(self.device.working_directory, self.tarname)
            on_host_tarball = self.device.path.join(context.output_directory, self.tarname + ".gz")
            self.device.execute('{} tar cf {} -C {} .'.format(self.device.busybox,
                                                              on_device_tarball,
                                                              self.tmpfs_mount_point),
                                as_root=True)
            self.device.execute('chmod 0777 {}'.format(on_device_tarball), as_root=True)
            self.device.execute('{} gzip {}'.format(self.device.busybox,
                                                    on_device_tarball))
            self.device.pull_file(on_device_tarball + ".gz", on_host_tarball)
            with tarfile.open(on_host_tarball, 'r:gz') as tf:
                tf.extractall(context.output_directory)
            self.device.delete_file(on_device_tarball + ".gz")
            os.remove(on_host_tarball)
    
        for paths in self.device_and_host_paths:
            after_dir = paths[self.AFTER_PATH]
