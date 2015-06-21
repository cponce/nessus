import time
import collections
import functools
import readline  #NOQA
import sys
import getpass  #NOQA
import json
import re
import percache
from operator import itemgetter
from tabulate import tabulate
from datetime import datetime

import requests
# from munch import munchify, unmunchify  # NOQA
import munch

from config import url, username, password, verify, token

# TODO - add doctests

FILE_FORMATS = ['nessus', 'html', 'pdf', 'csv', 'db']

CHAPTERS_DESC = {
    'vuln_hosts_summary': 'Executive Summary',
    'vuln_by_host': 'By Host',
    'vuln_by_plugin': 'By Vulnerability',
    'compliance-exec': 'Compliance Executive Summary',
    'compliance': 'Compliance Report',
    'remediations': 'Remediations'}

WIN_PATCH_REGEX = [re.compile(r'MS KB\d{6,7}'),
                   re.compile(r'MS\d{2,2}-\d{3,3}')]

SEVERITY = {
    4: 'Critical',
    3: 'High',
    2: 'Medium',
    1: 'Low',
    0: 'Info'}

# Disable warning for SSL certificates that cannot be trusted
# (for example, self-signed certs)
# TODO - handle this exception as one would handle it when using a browser
requests.packages.urllib3.disable_warnings()

# Cache for plugin attributes
plugin_cache = percache.Cache('tmp/plugin-attributes')

# Clear any entries older than 15 days from the plugin cache
plugin_cache.clear(maxage=60*60*24*15)


class TooManyUsers(Exception):
    pass


class InexistentSession(Exception):
    pass


class InsufficientPriv(Exception):
    pass


class memoized(object):
    '''Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    '''
    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            # uncacheable. a list, for instance.
            # better to not cache than blow up.
            return self.func(*args)
        if args in self.cache:
            return self.cache[args]
        else:
            value = self.func(*args)
            self.cache[args] = value
            return value

    def __repr__(self):
        '''Return the function's docstring.'''
        return self.func.__doc__

    def __get__(self, obj, objtype):
        '''Support instance methods.'''
        return functools.partial(self.__call__, obj)


def build_url(url, resource, params=None):
    # TODO - Deal with the invalid certificate exception, bad and malformed urls
    # and other exceptions

    if params is not None:
        full_url = '{}/{}/{}'.format(url, resource, params)
    else:
        full_url = '{}/{}'.format(url, resource)

    try:
        requests.get(full_url, verify=False)
    except requests.exceptions.ConnectionError:
        print('A connection error has ocurred. Please check the URL and \
port for errors. Exiting...')
        sys.exit()
    except requests.exceptions.HTTPError:
        print('Invalid HTTP response. Exiting...')
        sys.exit()
    else:
        return full_url


def build_headers():
    """
    Returns the headers.
    """
    return {'X-Cookie': 'token={}'.format(token),
            'content-type': 'application/json'}


def login():
    """
    Login to Nessus. Asks for username and password.
    Returns a session token.
    """
    while True:
        # TODO - Remember to ask for password instead of having the
        # password hard-coded

        # username = input('Username: ')
        # login_info = json.dumps({'username': username,
        # 'password': getpass.getpass()})

        login_info = json.dumps({'username': username, 'password': password})
        resource = 'session'

        try:
            r = requests.post(build_url(url, resource), data=login_info,
                              headers=build_headers(), verify=verify)
            if r.status_code == 200:
                print("Logged in as '{}'.".format(username))
                return r.json()['token']
            elif r.status_code == 400 or r.status_code == 401:
                raise ValueError
            elif r.status_code == 500:
                raise TooManyUsers
        except ValueError:
            print('Invalid username or password. Please try again.')
            continue
        except TooManyUsers:
            print('Too many users are connected. Exiting...')
            sys.exit()


def logout():
    """
    Destroys the current session.
    """
    resource = 'session'
    try:  # TODO - Add exception when permissions are insufficient.
        r = requests.delete(build_url(url, resource),
                            headers=build_headers(), verify=verify)
        if r.status_code == 200:
            print('Session destroyed.')
            sys.exit()
        elif r.status_code == 403:
            raise InexistentSession
    except InexistentSession:
        print('Session does not exist.')


def get_scan_details(scan_id, history_id=None):
    """
    Implements the 'details' method of the 'scans' resource.
    Returns the details of a particular scan in json format.
    scan_id: internal id of the scan
    history_id: internal id of the historic data for the scan
    """
    # TODO - Add exception when permissions are insufficient.
    # TODO - Add other exceptions
    resource = 'scans'
    params = scan_id
    data = json.dumps({'history_id': history_id})
    r = requests.get(build_url(url, resource, params), headers=build_headers(),
                     data=data, verify=verify)
    return r.json()


def get_host_details(scan_id, host_id, history_id=None):
    """
    Implements the 'host-details' method of the 'scans' resource.
    Returns the details of a particular host in json format.
    scan_id: internal id of the scan
    host_id: internal id of the host
    history_id: internal id of the historic data for the scan
    """
    # TODO - Add exception when permissions are insufficient.
    # TODO - Add other exceptions
    resource = 'scans'
    params = '{}/hosts/{}'.format(scan_id, host_id)
    data = json.dumps({'history_id': history_id})
    r = requests.get(build_url(url, resource, params), headers=build_headers(),
                     data=data, verify=verify)
    return r.json()


def get_scan_list(folder_id=None, last_modification_date=None):
    """
    Implements the 'list' method of the 'scans' resource.
    Returns a list of scans in json format.
    folder_id: internal id of the folder
    last_modification_date: last modification date of the folder
    """
    # TODO - Add exception when permissions are insufficient.
    # TODO - Add other exceptions
    resource = 'scans'
    data = json.dumps({'folder_id': folder_id,
                       'last_modification_date': last_modification_date})
    r = requests.get(build_url(url, resource), headers=build_headers(),
                     data=data, verify=verify)

    return r.json()


def get_folder_list():
    """
    Implements the 'list' method of the 'folders' resource.
    Returns a list of folders in json format.
    """
    resource = 'folders'
    r = requests.get(build_url(url, resource), headers=build_headers(),
                     verify=verify)
    if r.status_code == 403:
        raise InsufficientPriv('The user does not have sufficient privileges \
to access this resource')

    return r.json()


def fetch_folders(json_data, folder_id=None):
    d, folders = {}, get_folder_list()
    field_list = [k for k in folders[0]]
    Folder = collections.namedtuple('Folder', field_list)

    for el in folders:
        gen = (v for k, v in el.items())
        d[el['id']] = Folder._make(gen)

    if folder_id is None:
        return d
    elif isinstance(folder_id, int):
        try:
            d[folder_id]
        except KeyError:
            print('No folder with that id.')
            raise
        else:
            return {folder_id: d[folder_id]}
    else:
        raise ValueError('folder_id must be int or None.')


class Scan(object):
    def __init__(self, **entries):
        self.__dict__.update(entries)

    """
    def __init__(self, control, creation_date, enabled, folder_id, id,
                 last_modification_date, name, owner, read, rrules, shared,
                 starttime, status, timezone, user_permissions, uuid):
        self.control = control
        self.creation_date = creation_date
        self.enabled = enabled
        self.folder_id = folder_id
        self.id = id
        self.last_modification_date = last_modification_date
        self.name = name
        self.owner = owner
        self.read = read
        self.rrules = rrules
        self.shared = shared
        self.starttime = starttime
        self.status = status
        self.timezone = timezone
        self.user_permissions = user_permissions
        self.uuid = uuid
        self.hosts = []
    """


class Folder(object):
    def __init__(self, custom, default_tag, id, name, type, unread_count):
        self.custom = custom
        self.default_tag = default_tag
        self.id = id
        self.name = name
        self.type = type
        self.unread_count = unread_count


def sanitize_bad_entries(func):
    def wrapper(*args, **kwargs):
        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, dict):
                new_value = {}
                for k2, v2 in v.items():
                    if '-' in k2:
                        new_value[k2.replace('-', '_')] = v2
                    else:
                        new_value[k2] = v2
                new_kwargs[k] = munch.munchify(new_value)
            else:
                new_kwargs[k] = v
        return func(*args, **new_kwargs)
    return wrapper


class Host(object):
    @sanitize_bad_entries
    def __init__(self, scan_id, host_id, **entries):
        self.scan_id = scan_id
        self.host_id = host_id
        self.plugin_outputs_list = []
        self.__dict__.update(munch.munchify(entries))

    def __repr__(self):
        return "Host information:\n  Hostname: {}\n  IP Address: {}\n  \
Operating System: {}".\
            format(self.info.netbios_name, self.info.host_ip,
                   self.info.operating_system)

    def plugin_outputs(self):
        for el in self.vulnerabilities:
            json_data = get_plugin_output(self.scan_id, self.host_id,
                                          el.plugin_id)
            self.plugin_outputs_list.append(PluginOutput(**json_data))

    """
    def __init__(self, critical, high, host_id, host_index, hostname, info, low,
                 medium, numchecksconsidered, progress, scanprogresscurrent,
                 scanprogresstotal, score, severity, severitycount,
                 totalchecksconsidered):
        self.critical = critical
        self.high = high
        self.host_id = host_id
        self.host_index = host_index
        self.hostname = hostname
        self.info = info
        self.low = low
        self.medium = medium
        self.numchecksconsidered = numchecksconsidered
        self.progress = progress
        self.scanprogresscurrent = scanprogresscurrent
        self.scanprogresstotal = scanprogresstotal
        self.score = score
        self.serverity = severity
        self.serveritycount = severitycount
        self.totalchecksconsidered = totalchecksconsidered
    """


class PluginOutput(object):
    @sanitize_bad_entries
    def __init__(self, **entries):
        self.__dict__.update(munch.munchify(entries))


def deserializer(json_data):
    return json.loads(json.dumps(json_data, sort_keys=True))


def process_scans(folder_id=None, last_modification_date=None):
    d, json_data = collections.defaultdict(list), get_scan_list()
    scans, folders = json_data['scans'], json_data['folders']

    field_list = [k for k in scans[0]]
    Scan = collections.namedtuple('Scan', field_list)

    for el in scans:
        gen = [v for k, v in el.items()]
        d[el['folder_id']].append(Scan._make(gen))

    for folder in folders:
        if folder['id'] not in d:
            d[folder['id']].append(None)

    if folder_id is None:
        return d
    elif folder_id not in d:
        raise KeyError('folder_id not found.')
    else:
        return {folder_id: d[folder_id]}


def print_folders_contents(folder_id=None, last_modification_date=None):
    """
    Prints a lists of folders and their scans.
    d: dictionary containing folders as keys and scan named tuples as values.
    """
    scans_dict = process_scans(folder_id, last_modification_date)
    folders = get_folder_list()["folders"]
    folder_names = dict([(folder['id'], folder['name']) for folder in folders])

    for folder_id, scans in sorted(scans_dict.items()):
        print('\n(+) Folder name: {} - id: {}'.format(folder_names[folder_id],
                                                      folder_id))
        for scan in scans:
            if scan is None:
                print('  Folder is empty.\n')
            else:
                print('  id: {}  name:{}'.format(scan.id, scan.name))
    print('')


def post_export(scan_id, file_format='pdf', password=None, chapters=None,
                history_id=None):
    """
    Implements the 'export' method of the 'scans' resource.
    Returns the file id.
    """
    # TODO - Add functionality for other file types
    # TODO - Check exceptions
    export_info = json.dumps({'format': file_format, 'password': password,
                              'chapters': chapters, 'history_id': history_id})
    resource = 'scans'
    params = '{}/export'.format(scan_id)

    r = requests.post(build_url(url, resource, params), headers=build_headers(),
                      data=export_info, verify=verify)

    if r.status_code == 200:
        file_id = r.json()['file']
        while not get_export_status(scan_id, file_id):
            time.sleep(0.3)
    elif r.status_code == 400:
        print('A required parameter is missing.')
        sys.exit()
    elif r.status_code == 404:
        print('Scan does not exist.')
        sys.exit()
    return file_id


def get_export_status(scan_id, file_id):
    """
    Implements the 'export-status' method of the 'scans' resource.
    Returns the status of the file_id
    """
    resource = 'scans'
    params = '{}/export/{}/status'.format(scan_id, file_id)

    r = requests.get(build_url(url, resource, params),
                     headers=build_headers(), verify=verify)

    if r.status_code == 404:
        print('File does not exist.')
    elif r.status_code == 200:
        return r.json()['status'] == 'ready'


def get_download(scan_id, file_id, path, filename):
    """
    Implements the 'download' method of the 'scans' resource.
    Downloads the file.
    """
    resource = 'scans'
    params = '{}/export/{}/download'.format(scan_id, file_id)

    r = requests.get(build_url(url, resource, params),
                     headers=build_headers(), verify=verify)

    if r.status_code == 404:
        print('File does not exist.')
        sys.exit()
    elif r.status_code == 200:
        # TODO - add a try/except block to check for os exceptions
        # TODO - add a finally statement to close the file
        with open(path+filename, 'wb') as f:
            f.write(r.content)
        print("   File downloaded as '{}'".format(filename))


def fetch_chap_desc(chapter):
    """
    Returns a description for 'chapter'.  'Chapter' can be a single chapter
    or multiple chapters separated with semicolons (;)
    chapter: a valid chapter
    """
    res = ['Nessus Results']
    for chap in chapter.split(';'):
        res.append(CHAPTERS_DESC[chap])
    return ' - '.join(res)


def batch_decorator(func):
    def wrapper(*args, **kwargs):
        if kwargs['file_format'] not in FILE_FORMATS:
            raise ValueError('Invalid file format.')
        elif kwargs['file_format'] == 'pdf' or kwargs['file_format'] == 'html':
            for chapter in kwargs['chapters']:
                for x in chapter.split(';'):
                    if x not in CHAPTERS_DESC:
                        raise ValueError('Invalid chapter.')
        return func(*args, **kwargs)
    return wrapper


@batch_decorator
def batch_download(folders, file_format, path, chapters=None, password=None,
                   history_id=None):
    """
    Downloads Nessus reports in batches.

    folders: list of folder id's
    file_format: a list of file formats to be processed.
    path: full or relative path of the directory to which download the file(s)
    chapters: list of chapters to include in the report.
    password: password used to encrypt a 'db' file
    """
    # TODO - Add functionality to generate reports in multiple file formats
    # TODO - Is this helper function really necessary?
    def get_scans_to_download(folders):
        res = []
        for folder_id in folders:
            for folder, scans in process_scans(folder_id).items():
                for scan in scans:
                    res.append(scan)
        return res

    scan_list = get_scans_to_download(folders)
    num_scans = len(scan_list)

    print("Preparing to generate and download '{}' files for {} scans. This \
might take a while depending on the size of the files..."
          .format(file_format, num_scans))
    print("Download directory: '{}''\n".format(path))
    count = 1

    for scan in scan_list:
        print("Downloading scan results for '{}' scan... ({} of {})".
              format(scan.name, count, num_scans))
        count += 1
        if file_format == 'pdf' or file_format == 'html':
            for chapter in chapters:
                file_id = post_export(scan.id, file_format=file_format,
                                      chapters=chapter,
                                      history_id=history_id)
                filename = '{}_{}_{}.{}'.format(scan.name, file_id,
                                                fetch_chap_desc(chapter),
                                                file_format)
                get_download(scan.id, file_id, path, filename)
        else:
            file_id = post_export(scan.id, file_format=file_format,
                                  password=password, history_id=history_id)
            filename = '{}_{}.{}'.format(scan.name, file_id, file_format)
            get_download(scan.id, file_id, path, filename)


def operating_systems_report(scan_id):
    scan_details, d = get_scan_details(scan_id), collections.defaultdict(list)

    for host in scan_details['hosts']:
        host_details = get_host_details(scan_id, host['host_id'])
        try:
            key = host_details['info']['operating-system']
        except KeyError:
            d['Unidentified'].append(host['hostname'])
        else:
            d[key.replace('\n', ' | ')].append(host['hostname'])
    return d


@plugin_cache
def get_plugin_attrs(plugin_id):
    """
    Implements the 'plugin_details' method of the 'plugins' resource.
    Returns details of the plugin in json format.
    """
    resource = 'plugins'
    params = 'plugin/{}'.format(plugin_id)

    r = requests.get(build_url(url, resource, params),
                     headers=build_headers(), verify=verify)

    if r.status_code == 404:
        raise ValueError('Plugin does not exist.')
    elif r.status_code == 200:
        return r.json()


def plugin_attrs(plugin_id, attr_name=''):
    """
    Returns the value corresponding to the given attribute name (`attr_name`).
    If `attr_name` is an empty string then it returns a list containing all
    attribute names and values as dictionaries.
    If `attr_name` cannot be found, it raises a `ValueError` exception.
        plugin_id: int representing the plugin id
        attr_name: list of attribute names
    """
    try:
        plugin_attributes = get_plugin_attrs(plugin_id)['attributes']
    except ValueError:
        raise ValueError('Incorrect plugin id.')
    else:
        if not attr_name:
            return plugin_attributes
        for el in plugin_attributes:
            if el['attribute_name'] == attr_name:
                return el['attribute_value']
        raise ValueError('Plugin attribute not found')


def get_plugin_output(scan_id, host_id, plugin_id, history_id=None):
    """
    Implements the `plugin_output` method of the `scans` resource.
    Returns the plugin output for a given host, in json format.
    """
    resource = 'scans'
    params = '{}/hosts/{}/plugins/{}'.format(scan_id, host_id, plugin_id)

    r = requests.get(build_url(url, resource, params),
                     headers=build_headers(), verify=verify)

    if r.status_code == 404:
        raise ValueError('Scan does not exist.')
    elif r.status_code == 200:
        return r.json()


def gen_missing_patches(scan_id):
    scan_details = get_scan_details(scan_id)

    for vuln in scan_details['vulnerabilities']:
        for regex in WIN_PATCH_REGEX:
            if regex.match(vuln['plugin_name']) is not None:
                patch_id = regex.match(vuln['plugin_name']).group()
                plugin_id = vuln['plugin_id']
                count, severity = vuln['count'], vuln['severity']
                yield patch_id, plugin_id, severity, count


def build_missing_patches_report(scan_ids):
    """
    Takes a list of scan_ids and returns a defaultdict summarizing the
    operating system patches missing on the Windows systems in the scan
    list.
        scan_ids: list of scans to process
    """
    def prepare_table(scan_ids):
        d = collections.defaultdict(list)
        scan_patches = collections.defaultdict(list)
        res = []
        attr_name = 'patch_publication_date'

        for scan_id in scan_ids:
            for patch_id, plugin_id, severity, count\
                    in gen_missing_patches(scan_id):
                d[patch_id] = [plugin_id, severity, patch_id,
                               SEVERITY[severity]]
                scan_patches[scan_id].append([patch_id, count])

        for patch in d:
            for scan_id in scan_ids:
                patches, counts = zip(*scan_patches[scan_id])
                if patch in patches:
                    i = patches.index(patch)
                    d[patch].extend([counts[i]])
                else:
                    d[patch].extend([''])

        for k, v in d.items():
            try:
                patch_pub_date = plugin_attrs(v[0], attr_name)
            except ValueError:
                patch_pub_date = 'N/A'

            if patch_pub_date != 'N/A':
                patch_pub_date = datetime.strptime(patch_pub_date, '%Y/%m/%d')
            v.insert(3, patch_pub_date)
            res.append(v)

        return res

    result = prepare_table(scan_ids)
    headers = ['Patch ID', 'Patch Pub. Date', 'Severity']
    scan_names = [get_scan_details(scan_id)['info']['name']
                  for scan_id in scan_ids]
    headers.extend(scan_names)

    return result, headers


def print_missing_patches_report(scan_ids):
    """
    Takes a list of scan_ids and prints a report of missing operating system
    patches on Windows systems found in the scans.
    scan_ids: list of scans to process.
    """
    table, headers = build_missing_patches_report(scan_ids)
    sorted_by_severity = sorted(table, key=itemgetter(2), reverse=True)
    sorted_by_date = sorted(sorted_by_severity, key=itemgetter(1), reverse=True)
    print(tabulate([el[2:] for el in sorted_by_date], headers=headers))


if __name__ == '__main__':
    pass
