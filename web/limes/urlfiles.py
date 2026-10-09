import glob
import os
import re


def merge_url_files(results_dir, input_path, output_path, ignore_exts=()):
    pattern = re.compile(r'\.(' + '|'.join(map(re.escape, ignore_exts)) + r').*', re.I) if ignore_exts else None
    paths = sorted(glob.glob(os.path.join(results_dir, 'urls_*')))
    if os.path.exists(input_path):
        paths.append(input_path)
    urls = set()
    for path in paths:
        with open(path, errors='replace') as f:
            for line in f:
                url = line.strip()
                if url and not (pattern and pattern.search(url)):
                    urls.add(url)
    with open(output_path, 'w') as f:
        f.writelines(u + '\n' for u in sorted(urls))
    return len(urls)
