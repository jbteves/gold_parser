import logging
import pydicom
import gzip
import traceback
import warnings
import rapidjson as json
import base64
import sys

from subprocess import STDOUT, run, CalledProcessError, PIPE
from pathlib import Path
from collections import OrderedDict
from Crypto.Hash import SHA512


# Load the functions to read CSA Headers and ignore the warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore", category=UserWarning)
    from nibabel.nicom.csareader import get_csa_header, is_mosaic, CSAError, CSAReadError


def init_log(log_fpath, debug=False):

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s\n',
                        datefmt='%m-%d %H:%M',
                        filename=str(log_fpath),
                        filemode='w')

    # Set the root logger to stream the messages to console
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    logging.getLogger('').addHandler(console)

    return logging


def parse_date(date):
    if date != "*":
        if date.isdigit():
            if len(date) == 1:
                return "0{}".format(date)
            else:
                return date
        else:
            raise ValueError("Date selection must be integers (as 1 or 2 digits for day "
                             "and month, and 4 digit year)")
    return date


def sanitize_unicode(s):
    """Removes any \u0000 characters from unicode strings in DICOM values, since this character is
    unsupported in JSON"""

    if type(s) is bytes:
        s = s.decode('utf-8')
    return str(s).replace(u"\u0000", "").strip()


def parse_pn(value):
    """Parses a Person Name (VR of type PN) DICOM value into the appropriate JSON Model Object representation"""

    pn = OrderedDict({
        'Alphabetic': str(value)
    })

    if value.ideographic:
        pn["Ideographic"] = value.ideographic

    if value.phonetic:
        pn["Phonetic"] = value.phonetic

    return pn


def parse_seq(seq):
    """Parses a sequence (VR of type SQ) of DICOM values into the appropriate JSON Model Object representation"""

    vals = []

    for element in seq.value:
        if element:
            vals.append(parse_dicom_dataset(element))
        else:
            vals.append(None)
    return vals


def parse_at(value):
    return str(value).replace("(", "").replace(")", "").replace(", ", "")


def parse_ui(value):
    return str(repr(value).replace('"', '').replace("'", ""))


def _vr_encoding(vr):
    """A map of DICOM VRs to corresponding JSON types as specified in the DICOMweb standard"""

    vr_json_encodings = {
        'AE': sanitize_unicode,
        'AS': sanitize_unicode,
        'AT': parse_at,
        'CS': sanitize_unicode,
        'DA': sanitize_unicode,
        'DS': float,
        'DT': sanitize_unicode,
        'FL': float,
        'FD': float,
        'IS': int,
        'LO': sanitize_unicode,
        'LT': sanitize_unicode,
        'PN': parse_pn,
        'SH': sanitize_unicode,
        'SL': int,
        'SS': int,
        'ST': sanitize_unicode,
        'TM': sanitize_unicode,
        'UC': sanitize_unicode,
        'UI': parse_ui,
        'UL': int,
        'UR': sanitize_unicode,
        'US': int,
        'UT': sanitize_unicode
    }

    return vr_json_encodings[vr]


def encode_element(dicom_element):
    """Creates the appropriate JSON Model Object representation for a DICOM element"""

    if dicom_element.VR == 'SQ':

        return OrderedDict({
            'vr': dicom_element.VR,
            'Value': parse_seq(dicom_element)
        })

    elif pydicom.dataelem.isMultiValue(dicom_element.value):

        vals = []

        for val in dicom_element.value:
            if val != '' and val is not None:
                vals.append(_vr_encoding(dicom_element.VR)(val))
            else:
                vals.append(None)

        return OrderedDict({
            'vr': dicom_element.VR,
            'Value': vals
        })

    elif type(dicom_element.value) == pydicom.dataset.Dataset:

        return OrderedDict({
            'vr': dicom_element.VR,
            'Value': [parse_dicom_dataset(dicom_element.value)]
        })

    else:

        model_obj = OrderedDict({
            'vr': dicom_element.VR
        })

        # The conditions inside the or clause needed because numeric values of 0 will fail the
        # first part of the if clause. We really only want to exclude empty strings.
        if dicom_element.value or (dicom_element.value != '' and dicom_element.value != b''):
            model_obj["Value"] = [_vr_encoding(dicom_element.VR)(dicom_element.value)]

        return model_obj


def parse_dicom_dataset(dicom_dataset):
    """Parses a DICOM dataset and converts the DICOM elements into their appropriate JSON Model Object
    representations"""

    dicom_dict = OrderedDict()

    for dicom_element in dicom_dataset:

        tag = "".join(str(dicom_element.tag).lstrip("(").rstrip(")").split(", ")).upper()

        if dicom_element.VR in ('OB', 'OD', 'OF', 'OL', 'OW', 'UN'):

            dicom_dict[tag] = OrderedDict({
                'vr': dicom_element.VR,
                'Available': True
            })

        else:

            dicom_dict[tag] = encode_element(dicom_element)

    return dicom_dict


def decode_ge_private_data(byte_seq):
    """Attempts to uncompress the data in the (0x0025, 0x101B) field of GE Scans, which contains
    useful metadata for DTI scans"""

    log = logging.getLogger('')

    # Find the beginning of the GZIP sequence, and drop the padding bytes before it
    pos = byte_seq.find(b"\x1f\x8b")

    if pos == -1:

        return None

    else:

        try:

            uncompressed_bytes = gzip.decompress(byte_seq[pos:])

            decoded_bytes = uncompressed_bytes.decode('ascii').strip().split("\n")

            private_dat = OrderedDict()

            for item in decoded_bytes:
                first_space = item.find(" ")

                key = item[:first_space + 1].strip()

                val = item[first_space:].replace('"', '').strip()

                private_dat[key] = val

            return private_dat

        except (ValueError, OSError, TypeError, AttributeError, KeyError) as e:

            log.error("Error decoding GE private data\n")
            log.error(e)
            log.error(traceback.format_exc())

            return None


def parse_private_data(dicom_dataset):

    private_data = {
        'is_mosaic': False,
        'data': None
    }

    try:

        manufacturer = dicom_dataset[(0x0008, 0x0070)].value

        if "siemens" in manufacturer.lower():

            siemens_header = get_csa_header(dicom_dataset)

            if siemens_header:

                private_data['is_mosaic'] = is_mosaic(siemens_header)

                # Remove an unused key that is composed of random bytes and seems to be used for padding
                # (can't be converted to json easily)
                siemens_header.pop('unused0', None)

                # # For the remember of the entries, check that the values in the 'items' key of the 'tags'
                # # field in the header are of the proper type according to the specified VR for that tag.
                # # Additionally, ignore tags that are of VR SQ, PN, or any of the binary types.
                if siemens_header.get('tags', None):

                    for tag, val in siemens_header['tags'].items():

                        vr = val['vr']

                        if vr in ('OB', 'OD', 'OF', 'OL', 'OW', 'UN', 'SQ', 'PN'):
                            continue

                        sanitized_items = []

                        for item in val['items']:
                            sanitized_items.append(_vr_encoding(vr)(item))

                        siemens_header['tags'][tag]['items'] = sanitized_items

                # Make sure the remaining csa headers are json serializable, if not print error
                try:

                    _ = json.dumps(siemens_header)

                    private_data['data'] = siemens_header

                except TypeError:

                    pass

        elif ("ge" in manufacturer.lower()) or ("general electric" in manufacturer.lower()):

            ge_dat = dicom_dataset[(0x0025, 0x101B)].value

            ge_priv_data = decode_ge_private_data(ge_dat)

            if ge_priv_data:
                private_data['data'] = ge_priv_data

    except KeyError:

        pass

    except (CSAError, CSAReadError) as e:

        logging.error("Error reading CSA header")
        logging.error(e)
        logging.error(traceback.format_exc())

    return private_data


def parse_json_pn(alphabetic_pn):

    if not alphabetic_pn:
        return None

    try:
        pn = alphabetic_pn.split("^")
    except KeyError:
        return None

    res = {
        'family_name': '',
        'given_name': '',
        'middle_name': '',
        'prefix': '',
        'suffix': ''
    }

    try:
        res['family_name'] = pn[0]
    except IndexError:
        return None

    try:
        res['given_name'] = pn[1]
    except IndexError:
        pass

    try:
        res['middle_name'] = pn[2]
    except IndexError:
        pass

    try:
        res['prefix'] = pn[3]
    except IndexError:
        pass

    try:
        res['suffix'] = pn[4]
    except IndexError:
        pass

    return res


def get_checksum(filename, algorithm="md5"):

    cmd = "{}sum {}".format(algorithm, str(filename))

    try:
        res = run(cmd, check=True, shell=True, universal_newlines=True, stderr=STDOUT, stdout=PIPE)
        checksum = res.stdout.split(" ")[0]
    except CalledProcessError as e:
        checksum = None

        logging.error("Error computing checksum for file {}\n".format(filename))
        logging.error(e)
        logging.error(traceback.format_exc())

    return checksum


def get_exam_id(checksum, fpath):

    msg = str(checksum) + str(fpath)
    enc = base64.b64encode(msg.encode('utf-8'))
    h = SHA512.new(truncate="256")
    h.update(enc)
    return h.hexdigest()


def get_scan_id(exam_id, scan_name):

    msg = str(exam_id) + str(scan_name)
    enc = base64.b64encode(msg.encode('utf-8'))
    h = SHA512.new(truncate="256")
    h.update(enc)
    return h.hexdigest()


def get_scan_checksums(cmd):
    checksum_cmd = cmd[0]
    scan = cmd[1]

    try:
        run(checksum_cmd, check=True, shell=True, cwd=str(scan))
        msg = "Computing checksums for scan {}".format(scan)
    except CalledProcessError:
        msg = "Could not generate checksums for scan {}".format(scan)

    return msg


def list_files(scan_dir, out_file):

    scan_dir = Path(scan_dir)
    assert scan_dir.is_dir()

    cmd = "ls -U -1 {} > {}".format(scan_dir, out_file)

    try:
        run(cmd, check=True, shell=True, universal_newlines=True, stderr=STDOUT, stdout=PIPE)
    except CalledProcessError:
        logging.error("Error getting file list for scan {}".format(scan_dir))
