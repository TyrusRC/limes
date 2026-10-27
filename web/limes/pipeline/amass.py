"""OWASP Amass v5 integration: run enum, read names from its asset DB.

NOTE: v5 writes to an asset DB under `-dir`; results are read with
`amass subs`, not from a text file. `-dir` is the per-scan config/results
dir so runs don't collide.
"""
import os
import re

DEFAULT_TIMEOUT = 30
WORDLIST_DIR = '/usr/src/wordlist'


def wordlist_path(name, directory=WORDLIST_DIR):
	"""Path of the named wordlist (`<name>.txt` inside directory), or None for anything but a plain name of an
	existing file. The name comes from engine YAML, so no '/', no '..'."""
	if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) or '..' in name:
		return None
	path = os.path.join(directory, f'{name}.txt')
	return path if os.path.isfile(path) else None


def build_enum_argv(domain, config_dir, active, brute, wordlist):
    argv = ['amass', 'enum', '-d', domain, '-dir', config_dir]
    if active:
        argv.append('-active')
    if brute:
        argv.append('-brute')
        if wordlist:
            argv += ['-w', wordlist]
    return argv


def build_subs_argv(domain, config_dir):
    return ['amass', 'subs', '-names', '-d', domain, '-dir', config_dir]


def parse_subs(output, domain):
    seen, names = set(), []
    suffix = '.' + domain.lower()
    for line in output.splitlines():
        name = line.strip().lower()
        if not name:
            continue
        if name == domain.lower() or name.endswith(suffix):
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names
