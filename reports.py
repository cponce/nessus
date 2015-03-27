import time
from collections import namedtuple
import readline  #NOQA
import sys
import getpass  #NOQA
import requests
import json

requests.packages.urllib3.disable_warnings()

url = 'https://localhost:8834'
verify = False
token = ''
username = 'cesar'
password = 'test'
# timeout = 3


"""
class Query(object):
    def __init__(self, url, resource, params, headers, verify=False,
                 data=None, token=''):
        self.url = url
        self.resource = resource
        self.params = params
        self.headers = headers
        self.verify = verify
        self.data = data

    def getMethod(self):
        return self.method

    def getUrl(self):
        return self.url

    def getResource(self):
        return self.resource

    def getParams(self):
        return self.params

    def getHeaders(self):
        return self.headers

    def getVerify(self):
        return self.verify

    def getData(self):
        return self.data

    def build_headers():
        return {'X-Cookie': 'token={}'.format(token),
                'content-type': 'application/json'}
"""


class InvalidUserOrPass(Exception):
    pass


class TooManyUsers(Exception):
    pass


class InexistentSession(Exception):
    pass


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
    global token

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


def get_scan_list():
    """
    Implements the 'list' method of the 'scans' resource.
    Returns a list of scans in json format.
    """
    resource = 'scans'
    # TODO - Add exception when permissions are insufficient.
    # TODO - Add other exceptions
    r = requests.get(build_url(url, resource), headers=build_headers(),
                     verify=verify)
    return r.json()


def extract_json_data(json_data, component):
    """
    Takes a json object and returns a dictionary with the folder
    id as key and a tuple of the other data as values
    """
    d, lst = {}, json_data[component]

    if lst is None:
        return None

    if component == 'folders' or component == 'scans':
        field_list = [key for key in lst[0]]
        NamedTuple = namedtuple(component.capitalize(), field_list)

        for x in lst:
            gen = (value for key, value in x.items())
            d[x['id']] = NamedTuple._make(gen)

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
    print()


def post_export(scan_id, file_format='pdf', password=None,
                chapters='vuln_hosts_summary', history_id=None):
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

    r = requests.post(build_url(url, resource, params),
                      headers=build_headers(), data=export_info, verify=verify)

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
        print('File downloaded as "{}"'.format(filename))


def batch_download(scans_by_folder_dict, folder_id):
    chapters = ['vuln_hosts_summary', 'vuln_by_host', 'vuln_by_plugin']
    chap_desc = ['Nessus Results by Host - Executive Summary',
                 'Nessus Results by Host',
                 'Nessus Results by Vulnerability']
    file_format = 'pdf'

    folder_contents = list_folder_contents(scans_by_folder_dict, folder_id)
    num_scans = len(folder_contents)

    print('Preparing to download {} files for {} scans...'
          .format(file_format, num_scans))
    path = '/home/cesar/Projects/nessus/tests/'
    print('Download directory: "{}"'.format(path))
    count = 1

    for scan in folder_contents:
        print('Downloading scan results for "{}" scan... ({} of {})'.
              format(scan.name, count, num_scans))
        count += 1
        for chapter, desc in zip(chapters, chap_desc):
            file_id = post_export(scan.id, file_format=file_format,
                                  password=None, chapters=chapter,
                                  history_id=None)
            filename = '{}_{}_{}.{}'.format(scan.name, file_id, desc,
                                            file_format)
            get_download(scan.id, file_id, path, filename)


if __name__ == '__main__':
    token = login()
    """
    id_file = post_export(47)
    print(get_export_status(47, id_file))
    get_download(47, id_file)
    """
    scan_metadata = get_scan_list()
    folders_dict = extract_json_data(scan_metadata, 'folders')
    scans_dict = extract_json_data(scan_metadata, 'scans')
    scans_by_folder_dict = scans_by_folder(folders_dict, scans_dict)
    print_folders_contents(scans_by_folder_dict)
    batch_download(scans_by_folder_dict, 123)
    logout()
