# prompt_id=1715
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    def assemble_final_image(resized_images, output_path):
        final_name = pjoin(output_path, 'final/logos.png')
        random.shuffle(resized_images)
        values = {'images': ' '.join(resized_images), 'geometry': GEOMETRY,
                  'out_name': final_name}
        cmd = 'montage %(images)s -geometry %(geometry)s %(out_name)s'
        cmd = cmd % values
    
        print('Generating final image: %(name)s' % {'name': final_name})
        subprocess.call(cmd, shell=True)
    
    
    def main(input_path, output_path):
        if not os.path.exists(input_path):
            print('Path doesn\'t exist: %s' % (input_path))
            sys.exit(2)
    
        if not os.path.exists(output_path):
            print('Path doesn\'t exist: %s' % (output_path))
