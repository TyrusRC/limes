from limes.tasks.base import *

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def legacy_argv(cmd, shell):
	# NOTE: shell=True call sites remain until plan 0B rewrites the tool stages; they run through an explicit sh -c.
	return ['/bin/sh', '-c', cmd] if shell else shlex.split(cmd)


def _append_history(history_file, cmd, return_code, output):
	if history_file:
		with open(history_file, 'a') as f:
			f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')


@app.task(name='run_command', bind=False)
def run_command(
		cmd, 
		cwd=None, 
		shell=False, 
		history_file=None, 
		scan_id=None, 
		activity_id=None,
		remove_ansi_sequence=False,
		timeout=None
	):
	"""Run a given command using subprocess module.

	Args:
		cmd (str): Command to run.
		cwd (str): Current working directory.
		echo (bool): Log command.
		shell (bool): Run within separate shell if True.
		history_file (str): Write command + output to history file.
		remove_ansi_sequence (bool): Used to remove ANSI escape sequences from output such as color coding
		timeout (float): Kill the process group after this many seconds.
	Returns:
		tuple: Tuple with return_code, output.
	"""
	argv = legacy_argv(cmd, shell)
	shown = commands.display(argv)
	logger.info(shown)
	command_obj = Command.objects.create(
		command=shown,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)
	result = commands.run(argv, cwd=cwd, timeout=timeout, recorder=DbCommandRecorder(command_obj))
	output = result.output
	_append_history(history_file, shown, result.return_code, output)
	if remove_ansi_sequence:
		output = remove_ansi_escape_sequences(output)
	return result.return_code, output


#-------------#
# Other utils #
#-------------#

def stream_command(cmd, cwd=None, shell=False, history_file=None, encoding='utf-8', scan_id=None, activity_id=None, trunc_char=None, timeout=None, secrets=()):
	argv = legacy_argv(cmd, shell)
	shown = commands.display(argv, secrets)
	logger.info(shown)
	command_obj = Command.objects.create(
		command=shown,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)
	recorder = DbCommandRecorder(command_obj)
	for line in commands.stream(argv, cwd=cwd, timeout=timeout, recorder=recorder, secrets=secrets):
		line = ANSI_ESCAPE.sub('', line).replace('\\x0d\\x0a', '\n')
		if trunc_char and line.endswith(trunc_char):
			line = line[:-1]
		try:
			yield json.loads(line)
		except json.JSONDecodeError:
			yield line
	_append_history(history_file, shown, None, '')
