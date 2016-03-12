#!/usr/bin/python2
from __future__ import print_function
import argparse
import base64
import copy
import hashlib
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import urllib2
import urlparse
from collections import defaultdict
from datetime import datetime


__version__ = '0.0.1'


READ_SIZE = 65536
LOGGER = logging.getLogger('sig')


def touch_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)


def run(args, data=None, **kwargs):
    LOGGER.getChild('run').debug(' '.join(args))
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if data is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs
    )
    out, err = proc.communicate(data)
    return out, err, proc.returncode


TERM_FORMATS = {
    'BOLD': '1',
    'FAINT': '2',
    'BLACK': '30',
    'RED': '31',
    'GREEN': '32',
    'YELLOW': '33',
    'BLUE': '34',
    'MAGENTA': '35',
    'CYAN': '36',
    'WHITE': '37',
}


def color(text, *codes):
    parts = []
    parts.append('\033[')
    parts.append(';'.join(TERM_FORMATS[code] for code in codes))
    parts.append('m')
    parts.append(text)
    parts.append('\033[0m')
    return ''.join(parts)


class GPGError(Exception):
    pass


class GPGExitError(GPGError):
    pass


class GPGParseError(GPGError):
    pass


class GPGKeyNotFoundError(GPGError):
    pass


class GPGInvalidSignatureError(GPGError):
    pass


def gpg_run(args, data=None, keyring=None, secret_keyring=None, default_keyring=False):
    base_args = ['gpg', '--status-fd', '2']

    if not default_keyring:
        base_args.append('--no-default-keyring')

    if keyring:
        base_args.append('--keyring')
        base_args.append(keyring)

    if secret_keyring:
        base_args.append('--secret-keyring')
        base_args.append(secret_keyring)

    return run(base_args + args, data)


def gpg_parse_status(err):
    status = {}
    for line in err.decode('ascii').split('\n'):
        if line.startswith('[GNUPG:] '):
            fields = line.split(' ', 2)
            status[fields[1]] = fields[2] if len(fields) > 2 else True

    return status


def gpg_parse_colons(output):
    lines = output.decode('ascii').split('\n')
    sections = {}
    for line in lines:
        section, sep, content = line.partition(':')
        sections[section] = content.split(':')

    return {
        'uid': sections['pub'][8],
        'fingerprint': sections['fpr'][8],
    }


def gpg_check_run(*args, **kwargs):
    out, err, returncode = gpg_run(*args, **kwargs)
    if returncode != 0:
        raise GPGExitError(err.decode('ascii'))
    return out, err


def gpg_get_ascii_public_key(keyid, keyring=None):
    out, err = gpg_check_run([
        '--export',
        '--armor',
        keyid,
    ], keyring=keyring)
    if not out:
        raise GPGKeyNotFoundError
    return out


def gpg_get_key_info(keyid, keyring=None):
    LOGGER.getChild('gpg').debug('getting key info for {}'.format(keyid))
    try:
        out, err = gpg_check_run([
            '--with-colons',
            '--with-fingerprint',
            '--list-keys',
            keyid,
        ], keyring=keyring)
    except GPGExitError as e:
        if e.args[0] == 'gpg: error reading key: public key not found\n':
            raise GPGKeyNotFoundError
        else:
            raise
    return gpg_parse_colons(out)


def gpg_import_key(path, keyring=None):
    LOGGER.getChild('gpg').debug('importing key from {} to {}'.format(path, keyring))
    out, err = gpg_check_run([
        '--import',
        path,
    ], keyring=keyring)
    status = gpg_parse_status(err)
    return status['IMPORT_OK'].split(' ')[1]


def gpg_sign(keyid, text, keyring=None, secret_keyring=None):
    out, err = gpg_check_run([
        '--detach-sign',
        '--digest-algo=sha256',
        '-u',
        keyid,
        '-o',
        '-',
        '-',
    ], text.encode('ascii'), keyring, secret_keyring)
    return out


def gpg_verify(keyid, text, sig_data, keyring=None, default_keyring=False):
    pipe_rfd, pipe_wfd = os.pipe()
    os.write(pipe_wfd, text.encode('ascii'))
    os.close(pipe_wfd)
    out, err, returncode = gpg_run([
        '--verify',
        '--enable-special-filenames',
        '-',
        '-&{}'.format(pipe_rfd),
    ], sig_data, keyring, default_keyring=default_keyring)
    os.close(pipe_rfd)

    status = gpg_parse_status(err)

    if 'NO_PUBKEY' in status:
        raise GPGKeyNotFoundError('Unknown key')

    if 'VALIDSIG' not in status:
        raise GPGInvalidSignatureError('Invalid signature')

    validsig = status['VALIDSIG'].split(' ')
    sig_keyid = validsig[0]
    if sig_keyid != keyid:
        raise GPGInvalidSignatureError(
            'Key mismatch: got {}; expected {}'.format(sig_keyid, keyid)
        )

    # FIXME: this can apparently sometimes be an ISO 8601 string
    timestamp = datetime.fromtimestamp(int(validsig[2]))
    return timestamp


def make_attestation(data, keyid, keyring=None, secret_keyring=None):
    json_text = json.dumps(data, sort_keys=True)
    LOGGER.getChild('attestation').debug('signing as {}'.format(keyid))
    sig_data = gpg_sign(keyid, json_text, keyring, secret_keyring)

    attestation = {
        'data': data,
        'sig': base64.b64encode(sig_data).decode('ascii'),
        'key': keyid,
    }

    return attestation


def verify_attestation(attestation, keyring=None):
    sig_data = base64.b64decode(attestation['sig'])
    json_text = json.dumps(attestation['data'], sort_keys=True)
    LOGGER.getChild('attestation').debug('verifying from {}'.format(attestation['key']))
    return gpg_verify(attestation['key'], json_text, sig_data, keyring)


def identify(file_or_path):
    sha = hashlib.sha256()

    def read(f):
        while True:
            data = f.read(READ_SIZE)
            if not data:
                break
            sha.update(data)

    if type(file_or_path) is file:
        read(file_or_path)
    else:
        with open(file_or_path, 'rb') as f:
            read(f)

    return 'sha256:' + sha.hexdigest(), 'file'


class RepoNotFoundError(Exception):
    pass


class RepoUnreadableError(Exception):
    pass


class Repo(object):
    def __init__(self, path, keyid, keyring, secret_keyring):
        self.path = path
        self.keyid = keyid
        self.keyring = keyring
        self.secret_keyring = secret_keyring
        self.data = None

    def init_defaults(self):
        self.data = {}
        self.data['attestations'] = {}
        self.data['version'] = __version__

    def load(self):
        if not os.path.exists(self.path):
            raise RepoNotFoundError

        with open(self.path) as f:
            try:
                attestation = json.load(f)
            except ValueError:
                raise RepoUnreadableError

        verify_attestation(attestation, self.keyring)
        LOGGER.getChild('repo').debug('attestation ok')
        self.data = attestation['data']

    def save(self):
        LOGGER.getChild('repo').debug('saving to {} with keyid {}'.format(self.path, self.keyid))

        repo_attestation = make_attestation(
            self.data,
            self.keyid,
            self.keyring,
            self.secret_keyring,
        )

        with open(self.path, 'w') as f:
            json.dump(repo_attestation, f)

    def lookup(self, identity):
        return self.data['attestations'].get(identity)

    def add(self, attestation):
        identifier = attestation['data']['id']
        atts = self.data['attestations'].setdefault(identifier, [])
        atts.append(attestation)


class RepoSet(object):
    def __init__(self, repos):
        self.repos = repos

    def lookup(self, identity):
        results = []
        seen_sigs = set()
        for repo in self.repos:
            attestation_list = repo.lookup(identity)
            if not attestation_list:
                continue

            for attestation in attestation_list:
                if attestation['sig'] not in seen_sigs:
                    results.append(attestation)
                    seen_sigs.add(attestation['sig'])

        return results


class NoConfigError(Exception):
    pass


class ConfigExistsError(Exception):
    pass


class Config(object):
    DEFAULTS = {
        'repo_dir': 'repo/',
        'secret_keyring': None,
        'policy': {'ok': 1, 'not-ok': 0},
        'trust': {},
        'remotes': {},
    }

    def __init__(self, config_dir, keyid=None):
        self.config_dir = config_dir
        self.config = None
        self.keyid = keyid

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, value):
        self.config[key] = value

    def __contains__(self, key):
        return key in self.config or key in self.DEFAULTS

    def path(self, name):
        return os.path.join(self.config_dir, name)

    @property
    def repo_path(self):
        return self.path(os.path.join(self['repo_dir'], 'repo.json'))

    @property
    def keyring_path(self):
        return self.path('keyring.gpg')

    def _check_path(self, name):
        if not os.path.exists(self.path(name)):
            raise NoConfigError('Could not find {}'.format(name))

    def init_defaults(self):
        self.config = copy.deepcopy(self.DEFAULTS)

    def load(self):
        self._check_path('')
        self._check_path('config')
        self._check_path('keyring.gpg')

        with open(self.path('config')) as f:
            config_attestation = json.load(f)

        verify_attestation(config_attestation, self.keyring_path)
        LOGGER.getChild('config').debug('attestation ok')
        self.config = {}
        self.config.update(self.DEFAULTS)
        self.config.update(config_attestation['data'])
        self.keyid = config_attestation['key']

    def save(self):
        LOGGER.getChild('config').debug('saving to {} with keyid {}'.format(self.path('config'), self.keyid))

        self._check_path('')
        self._check_path('keyring.gpg')

        if not self.keyid:
            raise NoConfigError('No key specified')

        self.config['version'] = __version__

        config_attestation = make_attestation(
            self.config,
            self.keyid,
            self.keyring_path,
            self['secret_keyring'],
        )

        with open(self.path('config'), 'w') as f:
            json.dump(config_attestation, f)

    def get_repo(self, path):
        return Repo(
            path,
            self.keyid,
            self.keyring_path,
            self.config['secret_keyring'],
        )


class Sig(object):
    def load(self, config_dir=None):
        full_config_dir = os.path.expanduser(config_dir or '~/.signet')
        self.config = Config(full_config_dir)
        self.config.load()
        self.own_repo = self.config.get_repo(self.config.repo_path)
        self.own_repo.load()

        repos = [self.own_repo]
        failed_repos = {}
        for remote_name in self.config['remotes']:
            repo_path = self.config.path('remotes/{}/repo.json'.format(remote_name))
            remote_repo = self.config.get_repo(repo_path)
            try:
                # TODO: handle signature errors
                remote_repo.load()
            except RepoNotFoundError:
                # ok to ignore for now, repo might not be fetched yet
                pass
            except RepoUnreadableError as e:
                failed_repos[remote_name] = e
                continue
            repos.append(remote_repo)
        self.repos = RepoSet(repos)
        return failed_repos

    def setup_config_dir(self, keyid, config_dir=None):
        full_config_dir = os.path.expanduser(config_dir or '~/.signet')
        self.config = Config(full_config_dir, keyid=keyid)

        config_path = self.config.path('config')
        if os.path.exists(config_path):
            raise ConfigExistsError('Existing config detected at: {}'.format(config_path))

        public_key = gpg_get_ascii_public_key(keyid)

        touch_dir(self.config.path(''))
        touch_dir(self.config.path('repo'))
        touch_dir(self.config.path('remotes'))

        with open(self.config.path('repo/key.asc'), 'wb') as keyring_file:
            keyring_file.write(public_key)

        gpg_import_key(self.config.path('repo/key.asc'), self.config.keyring_path)

        self.config.init_defaults()
        self.config['trust'][keyid] = True

        self.config.save()

        own_repo = self.config.get_repo(self.config.repo_path)
        own_repo.init_defaults()
        own_repo.save()

    def get_key_info(self, keyid):
        return gpg_get_key_info(keyid, self.config.keyring_path)

    def attest(self, data):
        attestation = make_attestation(data, self.config.keyid, self.config.keyring_path)
        self.own_repo.add(attestation)
        self.own_repo.save()

    def validate(self, identifier):
        matches = {}

        def record_match(keyid, ts, kind):
            if keyid not in matches or ts > matches[keyid]['ts']:
                matches[keyid] = {'ts': ts, 'kind': kind}

        attestation_list = self.repos.lookup(identifier)

        for attestation in attestation_list:
            keyid = attestation['key']
            try:
                ts = verify_attestation(attestation, self.config.keyring_path)
            except GPGKeyNotFoundError:
                record_match(keyid, datetime.min, 'unknown')
                continue
            except GPGInvalidSignatureError:
                record_match(keyid, datetime.min, 'invalid')
                continue

            if attestation['data']['reviewed'] is not True:
                continue

            if self.config['trust'].get(keyid) is not True:
                record_match(keyid, ts, 'untrusted')
                continue

            if attestation['data']['ok'] is not True:
                record_match(keyid, ts, 'not-ok')
                continue

            record_match(keyid, ts, 'ok')

        categories = defaultdict(list)
        for keyid, match in matches.iteritems():
            categories[match['kind']].append(keyid)

        policy = self.config['policy']
        if not any(len(keys) > 0 for keys in categories.itervalues()):
            valid = None
        else:
            valid = len(categories['ok']) >= policy['ok'] and len(categories['not-ok']) <= policy['not-ok']
        return valid, categories

    def fetch_remote(self, name, remote, status_callback):
        def download(url):
            status_callback('start', {'url': url})
            resp = urllib2.urlopen(url)

            data = []
            while True:
                chunk = resp.read(READ_SIZE)
                if not chunk:
                    break
                data.append(chunk)

            status_callback('finish', {'url': url})
            return ''.join(data)

        repo_url = urlparse.urljoin(remote['url'], 'repo.json')
        repo_dir = self.config.path('remotes/{}'.format(name))
        touch_dir(repo_dir)
        repo_dest = os.path.join(repo_dir, 'repo.json')
        repo_data = download(repo_url)

        try:
            attestation = json.loads(repo_data)
        except ValueError as e:
            raise RepoUnreadableError(e)

        with open(repo_dest, 'w') as f:
            f.write(repo_data)

        try:
            gpg_get_key_info(attestation['key'], keyring=self.config.keyring_path)
        except GPGKeyNotFoundError:
            key_url = urlparse.urljoin(remote['url'], 'key.asc')
            key_dest = os.path.join(repo_dir, 'key.asc')
            download(key_url, key_dest)
            # TODO: check that key fingerprint matches expected
            imported_key_id = gpg_import_key(key_dest, keyring=self.config.keyring_path)
            status_callback('import', {'keyid': imported_key_id})


class CLILogFormatter(logging.Formatter):
    def __init__(self, color_func, verbose=False):
        self._c = color_func
        logging.Formatter.__init__(self)

    def format(self, record):
        text = []

        if record.levelno == logging.CRITICAL:
            text.append(self._c('!!!', 'BOLD', 'RED'))
        elif record.levelno == logging.ERROR:
            text.append(self._c('err', 'RED'))
        elif record.levelno == logging.WARNING:
            text.append(self._c('warning', 'YELLOW'))

        if record.name.startswith('sig.cli'):
            body = str(record.msg)
        else:
            body = '{name}: {message}'.format(
                name=record.name.replace('sig.', ''),
                message=record.msg,
            )

        if record.levelno == logging.DEBUG:
            text.append(self._c(body, 'FAINT'))
        else:
            text.append(body)

        return ' '.join(text)


class SigCLI(object):
    def __init__(self):
        self.sig = Sig()
        self.quiet = False
        self.use_color = True
        self.log = LOGGER.getChild('cli')

    def _c(self, text, *codes):
        if self.use_color:
            return color(text, *codes)
        return text

    def _init_args_parser(self):
        parser = argparse.ArgumentParser(prog='sig', formatter_class=WideHelpFormatter)
        parser.add_argument('--verbose', '-v', action='store_true', help='output detailed logs')
        parser.add_argument('--quiet', '-q', action='store_true', help='suppress status output')
        parser.add_argument('--no-color', action='store_true', help='don\'t colorize output')
        parser.set_defaults(subcommand=None)

        subparsers = parser.add_subparsers(title='subcommands', metavar='<command>', dest='command')

        parser_attest = subparsers.add_parser('setup', help='initialize configuration')
        parser_attest.add_argument('keyid')

        parser_verify = subparsers.add_parser('verify', help='check whether a resource is trusted')
        parser_verify.add_argument('file', nargs='?', default='-', help='a path to verify, or - for stdin')

        parser_attest = subparsers.add_parser('attest', help='sign a statement about a resource')
        parser_attest.add_argument('file')

        parser_fetch = subparsers.add_parser('fetch', help='download attestations from remotes')
        parser_fetch.add_argument('name', nargs='*', help='name of remote to fetch')

        subparsers.add_parser('publish', help='send attestations to remotes')

        parser_config = subparsers.add_parser('config', help='get and set configuration values', description='''
            When only a key is specified, the value of the config parameter is returned.
            If a value is specified, the config parameter is updated.''')
        parser_config.add_argument('key')
        parser_config.add_argument('value', nargs=argparse.REMAINDER)

        parser_trust = subparsers.add_parser('trust', help='manage trusted keys')
        subparsers_trust = parser_trust.add_subparsers(title='subcommands', metavar='<command>', dest='subcommand')

        subparsers_trust.add_parser('list', help='list trusted key policies')

        parser_trust_add = subparsers_trust.add_parser('add', help='trust a key when verifying resources')
        parser_trust_add.add_argument('keyid', help='id of the key to add')

        parser_trust_remove = subparsers_trust.add_parser('remove', help='remove trusted key')
        parser_trust_remove.add_argument('keyid', help='id of the key to remote')

        parser_remote = subparsers.add_parser('remote', help='manage remote repositories')
        subparsers_remote = parser_remote.add_subparsers(title='subcommands', metavar='<command>', dest='subcommand')

        subparsers_remote.add_parser('list', help='list configured remote repositories')

        parser_remote_add = subparsers_remote.add_parser('add', help='add a remote signet repository')
        parser_remote_add.add_argument('name', help='a nickname to refer to the remote')
        parser_remote_add.add_argument('url', help='the url of the remote')

        parser_remote_remove = subparsers_remote.add_parser('remove', help='remove a remote')
        parser_remote_remove.add_argument('name')

        parser_help = subparsers.add_parser('help', help='display this help')
        parser_help.add_argument('topic', nargs=argparse.REMAINDER, help='a command to display help for')

        return parser

    def load(self):
        failed_repos = self.sig.load(os.environ.get('SIG_DIR'))
        for remote_name, reason in failed_repos.iteritems():
            if type(reason) is RepoUnreadableError:
                self.log.warning('Unable to load remote repo "{}". Skipped.'.format(remote_name))

    def run(self, argv=None):
        parser = self._init_args_parser()

        args = parser.parse_args(argv)
        self.use_color = not args.no_color

        if args.command == 'help':
            parser.parse_args(args.topic + ['-h'])
            return

        command = args.command
        if args.subcommand:
            command += '_' + args.subcommand

        log_output = logging.StreamHandler(stream=sys.stdout)
        log_output.setFormatter(CLILogFormatter(
            color_func=self._c,
            verbose=args.verbose,
        ))
        self.quiet = args.quiet
        if args.verbose:
            LOGGER.setLevel(logging.DEBUG)
        elif args.quiet:
            LOGGER.setLevel(logging.CRITICAL)
        else:
            LOGGER.setLevel(logging.INFO)
        LOGGER.addHandler(log_output)

        if command != 'setup':
            self.load()

        getattr(self, 'cmd_' + command)(args)

    def _summarize_key(self, keyid):
        key_info = self.sig.get_key_info(keyid)
        return '[{fp}] {uid}'.format(
            uid=key_info['uid'],
            fp=key_info['fingerprint'][-8:]
        )

    def _lookup_key(self, keyid, keyring):
        try:
            return gpg_get_key_info(keyid, keyring=keyring)
        except GPGKeyNotFoundError:
            self.log.error('Key not found: {}'.format(keyid))
            sys.exit(1)

    def cmd_setup(self, args):
        full_keyid = self._lookup_key(args.keyid, keyring=None)['fingerprint']

        try:
            self.sig.setup_config_dir(full_keyid, os.environ.get('SIG_DIR'))
        except ConfigExistsError as e:
            self.log.error(e)
            self.log.info('Aborting.')
            sys.exit(1)

        self.log.info('Initialized config directory at: {}'.format(self.sig.config.path('')))
        self.log.info('With public key fingerprint: {}'.format(full_keyid))
        self.log.info('Welcome to Signet! :)')

    def cmd_attest(self, args):
        identifier, kind = identify(args.file)

        reviewed = None
        while reviewed not in ['yes', 'no']:
            reviewed = raw_input('I have reviewed this {} (yes/no): '.format(kind))

        if not reviewed == 'yes':
            self.log.info('Please review the file')
            return

        ok = None
        while ok not in ['yes', 'no']:
            ok = raw_input('It performs as expected and is free of major flaws (yes/no): '.format(kind))

        comment = raw_input('Comment: ')

        data = {
            'id': identifier,
            'ok': ok == 'yes',
            'reviewed': True,
        }

        if comment:
            data['comment'] = comment

        self.sig.attest(data)
        self.log.info('Saved attestation for {}:'.format(args.file))
        self.log.info(json.dumps(data, indent=2, sort_keys=True))

    def cmd_verify(self, args):
        # TODO: add verbose mode to display comments, timestamps, replacements, etc
        file_path = os.path.abspath(args.file)
        input_file = sys.stdin if args.file == '-' else file_path
        identifier, kind = identify(input_file)

        self.log.info('identified {} as {}'.format(kind, identifier))

        ok, matches = self.sig.validate(identifier)

        if ok is None:
            self.log.info('{} {} is {}!'.format(kind, file_path, self._c('unknown', 'YELLOW')))
            sys.exit(1)

        for category in ('unknown', 'invalid'):
            count = len(matches[category])
            if count > 0:
                self.log.info('{}: {}'.format(category, count))

        for category in ('ok', 'not-ok', 'untrusted'):
            for keyid in matches[category]:
                self.log.info('{} {}'.format(category, self._summarize_key(keyid)))

        if not ok:
            if len(matches['not-ok']) > 0:
                self.log.critical('{} {} is {}!'.format(kind, file_path, self._c('marked bad', 'BOLD', 'RED')))
            else:
                self.log.info('{} {} is {}.'.format(kind, file_path, self._c('not verified', 'YELLOW')))
            sys.exit(1)

        self.log.info('{} {} is {}.'.format(kind, file_path, self._c('ok', 'BOLD', 'GREEN')))

    def cmd_fetch(self, args):
        def print_status(event, details):
            if self.quiet:
                return

            if event == 'start':
                print('GET {}... '.format(details['url']), end='')
            elif event == 'finish':
                print('done.')
            elif event == 'import':
                print('Imported {}.'.format(self._summarize_key(details['keyid'])))

        for name, remote in self.sig.config['remotes'].iteritems():
            if args.name and name not in args.name:
                continue

            try:
                self.sig.fetch_remote(name, remote, print_status)
            except urllib2.HTTPError as e:
                if not self.quiet:
                    print(self._c(str(e), 'RED'))
            except RepoUnreadableError as e:
                self.log.warning('Unable to read remote repo "{}": {}'.format(name, e))

    def cmd_publish(self, args):
        self.log.info('Signet servers are not ready yet.')
        self.log.info('In the mean time, copy {} to a web server.'.format(self.sig.config['repo_dir']))

    def cmd_config(self, args):
        if args.key and args.key not in self.sig.config:
            self.log.error('Unknown key: {}'.format(args.key))
            sys.exit(1)

        if args.key and args.value:
            self.sig.config[args.key] = json.loads(' '.join(args.value))
            self.sig.config.save()
            return

        if args.key:
            self.log.info(json.dumps(self.sig.config[args.key], sort_keys=True))
            return

    def cmd_trust_list(self, args):
        for keyid, policy in self.sig.config['trust'].iteritems():
            self.log.info(self._summarize_key(keyid))

    def cmd_trust_add(self, args):
        full_keyid = self._lookup_key(args.keyid, keyring=self.sig.config.keyring_path)['fingerprint']

        if self.sig.config['trust'].get(full_keyid) is True:
            self.log.warning('Already trusted. Skipping.')
            return

        self.sig.config['trust'][full_keyid] = True
        self.sig.config.save()
        self.log.info('Trusted: {}'.format(self._summarize_key(full_keyid)))

    def cmd_trust_remove(self, args):
        full_keyid = self._lookup_key(args.keyid, keyring=self.sig.config.keyring_path)['fingerprint']

        if full_keyid not in self.sig.config['trust']:
            self.log.warning('Not trusted. Skipping.')
            return

        del self.sig.config['trust'][full_keyid]
        self.sig.config.save()
        self.log.info('Removed: {}'.format(self._summarize_key(full_keyid)))

    def cmd_remote_list(self, args):
        for name, config in self.sig.config['remotes'].iteritems():
            self.log.info('"{}" {}'.format(name, config['url']))

    def cmd_remote_add(self, args):
        if args.name in self.sig.config['remotes']:
            self.log.warning('A remote named "{}" already exists. Skipping.'.format(args.name))
            return

        self.sig.config['remotes'][args.name] = {'url': args.url}
        self.sig.config.save()

    def cmd_remote_remove(self, args):
        if args.name not in self.sig.config['remotes']:
            self.log.warning('No remote named "{}" exists. Skipping.'.format(args.name))
            return

        del self.sig.config['remotes'][args.name]
        self.sig.config.save()


class WideHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs):
        argparse.HelpFormatter.__init__(self, *args, **kwargs)
        self._action_max_length = 18


if __name__ == '__main__':
    SigCLI().run()
