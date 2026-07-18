# prompt_id=1822
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    if django_mailing:
        send_mail(subject, message, sender, [recipient])

    else:
        command = 'mail -s "{subject}" -r {sender} {recipient}'.format(
            subject=subject,
            sender=sender,
            recipient=recipient,
        )

        writer = os.popen(command, 'w')
        writer.write(message)
        writer.close()

if self.verbosity >= 2:
    # write only a header
    self.stdout.write('-' * 40 + '\n')
    self.stdout.write('To: {}\n'.format(recipient))
    self.stdout.write('Subject: {}\n'.format(subject))
    self.stdout.write('From: {}\n'.format(sender))
