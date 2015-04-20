import time
import collections
import functools
import readline  #NOQA
import sys
import getpass  #NOQA
import requests
import json
import re
from tabulate import tabulate
from operator import itemgetter

# TODO - add doctests
requests.packages.urllib3.disable_warnings()

FILE_FORMATS = ['nessus', 'html', 'pdf', 'csv', 'db']

CHAPTERS_DESC = {
    'default': 'Nessus Results - ',
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


class InvalidUserOrPass(Exception):
    pass


class TooManyUsers(Exception):
    pass


class InexistentSession(Exception):
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
    # TODO - check if it is a good idea for token to be a global variable
    # global token

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
                raise InvalidUserOrPass
            elif r.status_code == 500:
                raise TooManyUsers
        except InvalidUserOrPass:
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


def get_scan_list(folder_id=None, history_id=None):
    """
    Implements the 'list' method of the 'scans' resource.
    Returns a list of scans in json format.
    folder_id: internal id of the folder
    history_id: internal id of the historic data for the scans in the folder
    """
    # TODO - Add exception when permissions are insufficient.
    # TODO - Add other exceptions
    # TODO - Check that the docstring is correct
    resource = 'scans'
    data = json.dumps({'folder_id': folder_id, 'history_id': history_id})
    r = requests.get(build_url(url, resource), headers=build_headers(),
                     data=data, verify=verify)
    return r.json()


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


def extract_json_data(json_data, component, key_name):
    # TODO - is this function really necessary? check alternatives
    """
    Takes a json object and returns a dictionary with the folder
    id as key and a tuple of the other data as values
    """
    d, lst = {}, json_data[component]

    if lst is None:
        return None

    field_list = [key for key in lst[0]]
    NamedTuple = collections.namedtuple(component.capitalize(), field_list)

    for x in lst:
        gen = (value for key, value in x.items())
        d[x[key_name]] = NamedTuple._make(gen)

    return d


def scans_by_folder(folders_dict, scans_dict):
    """
    Generates a dictionary of folders and scans; folder_id is the key, value
    is a list of namedtuples representing scans.

    folders_dict: a dictionary of folders
    scans_dict: a dicitonary of scans
    """
    d = {}

    for folder_id, fields in folders_dict.items():
        d[folder_id] = []
        if scans_dict is not None:
            for scan_id, fields2 in scans_dict.items():
                if folder_id == fields2.folder_id:
                    d[folder_id].append(fields2)
    return d


def list_folder_contents(folders_scans_dict, folder_id):
    return folders_scans_dict[folder_id]


def print_folders_contents(d):
    """
    Prints a lists of folders and their scans.
    d: dictionary containing folders as keys and scan named tuples as values.
    """
    for folder_id, scans in d.items():
        print('\n(+) Folder name: {} - id: {}'.
              format(folders_dict[folder_id].name, folder_id))
        if scans == []:
            print('   Folder is empty.\n')
        else:
            for scan in scans:
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
        while get_export_status(scan_id, file_id) is False:
            time.sleep(2)
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
    elif r.status_code == 200:
        # TODO - add a try/except block to check for os exceptions
        with open(path+filename, 'wb') as f:
            f.write(r.content)
        print("File downloaded as '{}'".format(filename))


def are_chapters(chapters):
    """
    Returns True if all the chapters are valid; False otherwise.
    chapters: list of chapters.
    """
    for chapter in chapters:
        for chapter2 in chapter.split(';'):
            if chapter2 not in CHAPTERS_DESC:
                return False
    return True


def fetch_chap_desc(chapter):
    """
    Returns a description for 'chapter'.  'Chapter' can be a single chapter
    or multiple chapters separated with semicolons (;)
    chapter: a valid chapter
    """
    lst = ['Nessus Results -']
    for chap in chapter.split(';'):
        lst.append(CHAPTERS_DESC[chap])
    return ' '.join(lst)


def batch_decorator(func):
    def wrapper(*args, **kwargs):
        for name, value in kwargs.items():
            if name == 'file_format' and value not in FILE_FORMATS:
                print('Invalid file format. Exiting...')
                sys.exit()
        else:
            return func(*args, **kwargs)
    return wrapper


@batch_decorator
def batch_download(scans_by_folder_dict, folders, file_format, path,
                   chapters=None, password=None, history_id=None):
    """
    Downloads Nessus reports in batches.

    scans_by_folder_dict: dict containing folders (keys) and scans (values)
    folders: comma-separated string of folder id's
    file_format: format of the files to be processed and downloaded
    path: full or relative path of the directory to which download the file(s)
    chapters: comma-separated list of chapters to include in the report. If
    semicolon-delimited, a single file with the specified chapters will be
    generated
    password: password used to encrypt a 'db' file
    """
    d = collections.defaultdict(list)

    try:
        # Remove spaces from the folder list
        folders = folders.replace(' ', '').strip()

        # Check that the list of folders is valid and is composed of integers
        folder_set = set(int(x) for x in folders.split(','))
    except (ValueError, AttributeError):
        print("The 'folders' parameter must be a string of folder id's.")
        sys.exit()

    # Only execute chapter validation if the file format is either pdf or html
    if file_format == 'pdf' or file_format == 'html':
        chapters = chapters.replace(' ', '').strip()
        chapters_list = chapters.split(',')

        # Checks if chapter(s) is(are) valid
        if are_chapters(chapters_list) is False:
            print('Invalid chapters. Exiting...')
            sys.exit()

    # Populate the defaultdict with folder ids as keys and the folder's scans
    # as values
    for folder_id in folder_set:
        d[folder_id].extend(list_folder_contents(scans_by_folder_dict,
                                                 folder_id))

    # Generate a list of scans to be processed.
    scan_list = [scan for folder, scans in d.items() for scan in scans]
    num_scans = len(scan_list)

    print("Preparing to generate and download '{}' files for {} scans. This \
might take a while depending on the size of the files..."
          .format(file_format, num_scans))
    print("Download directory: '{}'".format(path))
    count = 1

    for scan in scan_list:
        print("--> Downloading scan results for '{}' scan... ({} of {})".
              format(scan.name, count, num_scans))
        count += 1
        if file_format == 'pdf' or file_format == 'html':
            for chapter in chapters_list:
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
        print('Plugin does not exist.')
    elif r.status_code == 200:
        return r.json()


@memoized
def plugin_attrs(plugin_id, attr_name):
    """
    Returns a defaultdict of attributes (keys) and attribute values (values)
    for a plugin, in a workable format.
    """
    # d = collections.defaultdict(list)

    for el in get_plugin_attrs(plugin_id)['attributes']:
        if el['attribute_name'] == attr_name:
            return el['attribute_value']
        # yield el['attribute_name'], el['attribute_value']
        # d[el['attribute_name']].append(el['attribute_value'])
    # return d


def gen_missing_patches(scan_id):
    """
    Genetator that returns the missing operating system patch and the IP
    address for each Windows system found in a given scan.
    scan_id: the id of the scan to process.
    """
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
    Takes a list of scan_ids and builds a defaultdict summarizing the
    operating system patches missing on the Windows systems found in the scans
    given as the parameter.
    scan_ids: list of scans to process.
    """
    d = collections.defaultdict(list)
    scan_patches = collections.defaultdict(list)
    res = []

    # field_list = ['plugin_id', 'severity_num', 'patch_id', 'patch_pub_date',
    #              'severity_desc']
    # field_list.extend(['scan_{}'.format(x) for x in range(len(scan_ids))])
    # PatchInfo = collections.namedtuple('PatchInfo', field_list)

    for scan_id in scan_ids:
        for patch_id, plugin_id, severity, count\
                in gen_missing_patches(scan_id):
            """
            d[patch_id] = PatchInfo(plugin_id=plugin_id, severity_num=severity,
                                    patch_id=patch_id, patch_pub_date=None,
                                    severity_desc=SEVERITY[severity], scan_
            """
            d[patch_id] = [plugin_id, severity, patch_id, SEVERITY[severity]]
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
        attr_name = 'patch_publication_date'
        patch_pub_date = plugin_attrs(v[0], attr_name)
        v.insert(3, patch_pub_date)
        # temp = [k]
        # temp.extend(v)
        res.append(v)

    headers = ['Patch ID', 'Patch Pub. Date', 'Severity']
    scan_names = [get_scan_details(scan_id)['info']['name']
                  for scan_id in scan_ids]
    headers.extend(scan_names)

    return res, headers


def print_missing_patches_report(scan_ids):
    """
    Takes a list of scan_ids and prints a report of missing operating system
    patches on Windows systems found in the scans.
    scan_ids: list of scans to process.
    """
    table, headers = build_missing_patches_report(scan_ids)
    sorted_table = sorted(table, key=itemgetter(1), reverse=True)
    print(tabulate([el[2:] for el in sorted_table], headers=headers))


def prev_gen_missing_patches(scan_id):
    """
    Genetator that returns the missing operating system patch and the IP
    address for each Windows system found in a given scan.
    scan_id: the id of the scan to process.
    """
    scan_details = get_scan_details(scan_id)

    for host in scan_details['hosts']:
        host_details = get_host_details(scan_id, host['host_id'])
        for vuln in host_details['vulnerabilities']:
            for regex in WIN_PATCH_REGEX:
                if regex.match(vuln['plugin_name']) is not None:
                    patch_id = regex.match(vuln['plugin_name']).group()
                    hostname = host['hostname']
                    yield patch_id, hostname


if __name__ == '__main__':
    pass
