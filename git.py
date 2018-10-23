import subprocess


def init(repopath):
    gitprocess = subprocess.run(
        ['git', '-C', repopath, 'init'])
    gitprocess = subprocess.run(
        ['git', '-C', repopath, 'config', 'user.email', 'null'])
    gitprocess = subprocess.run(
        ['git', '-C', repopath, 'config', 'user.name', 'null'])
    stamp(repopath, 'create pki')


def stamp(repopath, msg):
    print(repopath)
    gitprocess = subprocess.run(
        ['git', '-C', repopath, 'add', '-A'], encoding='ascii',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if gitprocess.returncode != 0:
        raise Exception()
    gitprocess = subprocess.run(
        ['git', '-C', repopath, 'commit', '--allow-empty', '-a', '-m', msg], encoding='ascii',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if gitprocess.returncode != 0:
        raise Exception()


def abort(repopath):
    gitprocess = subprocess.run(['git', '-C', repopath, 'reset', 'HEAD^'], encoding='ascii',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if gitprocess.returncode != 0:
        raise Exception()
