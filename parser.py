import os
import argparse
import shutil
import time
import logging
import traceback

from pathlib import Path
from multiprocessing.dummy import Pool as ThreadPool  # Use threads
from multiprocessing import Pool as ProcessPool
from subprocess import check_output, STDOUT
import pydicom
import rapidjson as json
from collections import OrderedDict
from pydicom.errors import InvalidDicomError


# Hack to load utils from sibling modules if running this from the CLI
if __name__ == "__main__" and __package__ is None:

    from sys import path

    from os.path import dirname

    path.append(dirname(path[0]))
    __package__ = "gold_parser"

    from .utils import (
        init_log,
        parse_dicom_dataset,
        parse_private_data,
        parse_date,
        get_checksum,
        encode_element,
        get_scan_checksums,
        get_exam_id,
        get_scan_id,
    )

else:

    from .utils import (
        init_log,
        parse_dicom_dataset,
        parse_private_data,
        parse_date,
        get_checksum,
        encode_element,
        get_scan_checksums,
        get_exam_id,
        get_scan_id,
    )

log = logging.getLogger('')


def do_full_tgz_extraction(args):
    """Uncompresses a TGZ image archive from Gold into the specified work directory, or inside a temporary directory
     with randomly generated name within the work directory"""

    compressed_file, settings = args

    compressed_file = Path(compressed_file)

    if not settings:
        log.error("Missing settings configuration for tgz extraction of {}".format(compressed_file))
        return False, [compressed_file]

    curr_scanner = compressed_file.parent.parent.parent.parent.parent.name
    curr_year = compressed_file.parent.parent.parent.parent.name
    curr_month = compressed_file.parent.parent.parent.name
    curr_day = compressed_file.parent.parent.name
    curr_exam_subdir = compressed_file.parent.name
    curr_file = compressed_file.name

    exam_checksum = get_checksum(compressed_file)

    id_fpath = "{}/{}/{}/{}/{}/{}".format(curr_scanner, curr_year, curr_month, curr_day, curr_exam_subdir, curr_file)

    exam_id = get_exam_id(exam_checksum, id_fpath)

    extract_dir = settings['work_dir'] / curr_scanner / curr_year / curr_month / curr_day / exam_id

    if not extract_dir.is_dir():
        extract_dir.mkdir(parents=True, exist_ok=True)

    cmd = "unpigz --keep < {} | tar -xC {}".format(str(compressed_file), str(extract_dir))

    try:
        check_output(cmd, stderr=STDOUT, shell=True)
        success = True
    except Exception:
        success = False

    if success:
        return success, [extract_dir, compressed_file, exam_id, exam_checksum]
    else:
        return success, [compressed_file]


def get_dicom_meta(args):

    dcm = Path(args[0])
    try:
        ge_extra_meta = args[1]
    except IndexError:
        ge_extra_meta = False

    try:
        dicom_dataset = pydicom.dcmread(str(dcm), stop_before_pixels=True)
    except InvalidDicomError as e:
        log.error("Unable to read: {}".format(str(dcm)))
        log.error(e)
        log.error(traceback.format_exc())
        return dcm, {'sop_instance_uid': None}

    if ge_extra_meta:

        dicom_data = {
            'echo_number': None,
            'raw_data_run_number': None,
            'image_position_patient': None,
            'sop_instance_uid': None,
        }

        try:
            echo_number = encode_element(dicom_dataset[(0x0018, 0x0086)])['Value'][0]
        except (KeyError, TypeError, AttributeError):
            echo_number = None

        try:
            raw_data_run_number = encode_element(dicom_dataset[(0x0019, 0x10A2)])['Value'][0]
        except (KeyError, TypeError, AttributeError):
            raw_data_run_number = None

        try:
            image_position_patient = encode_element(dicom_dataset[(0x0020, 0x0032)])['Value']
        except (KeyError, TypeError, AttributeError):
            image_position_patient = None

        try:
            sop_instance_uid = encode_element(dicom_dataset[(0x0008, 0x0018)])['Value'][0]
        except (KeyError, TypeError, AttributeError):
            sop_instance_uid = None

        dicom_data['echo_number'] = echo_number
        dicom_data['raw_data_run_number'] = raw_data_run_number
        dicom_data['image_position_patient'] = image_position_patient
        dicom_data['sop_instance_uid'] = sop_instance_uid

    else:

        dicom_data = {
            'sop_instance_uid': None,
        }

        try:
            sop_instance_uid = encode_element(dicom_dataset[(0x0008, 0x0018)])['Value'][0]
        except (KeyError, TypeError, AttributeError):
            sop_instance_uid = None

        dicom_data['sop_instance_uid'] = sop_instance_uid

    return dcm, dicom_data


def get_metadata(extracted_archives, parser_version):

    num_archives = len(extracted_archives)
    fcount = 1

    for extracted_archive, compressed_file, exam_id, exam_checksum in extracted_archives:

        log.info("Processing file {}/{}...".format(fcount, num_archives))
        fcount += 1

        start_extract = time.time()

        if not compressed_file.is_file():
            log.error("Original compressed file missing: {}".format(compressed_file))
            log.error("Removing extracted archive: {}".format(extracted_archive))
            shutil.rmtree(str(extracted_archive))
            continue

        session_dirs = list([session for session in Path(extracted_archive).glob("*/*") if session.is_dir()])

        if len(session_dirs) != 1:
            log.error("Invalid number of session directories for exam {}".format(compressed_file))
            log.error("Removing extracted archive: {}".format(extracted_archive))
            shutil.rmtree(str(extracted_archive))
            continue

        exam_dir = session_dirs[0]

        scans = [s for s in exam_dir.iterdir() if s.is_dir()]

        if not len(scans) > 0:
            log.error("No scans found in exam {}".format(compressed_file))
            log.error("Removing extracted archive: {}".format(extracted_archive))
            shutil.rmtree(str(extracted_archive))
            continue

        study_meta = OrderedDict({
             'metadata': OrderedDict({
                 'exam_id': exam_id,
                 'gold_fpath': "/".join(str(compressed_file).split("/")[-6:]),
                 'gold_archive_checksum': exam_checksum,
                 'parser_version': parser_version,
             }),
             'data': [],
         })

        for scan in scans:

            scan_start = time.time()

            scan_id = get_scan_id(exam_id, scan.name)

            instance_files = [f for f in scan.iterdir() if f.is_file() and "README" not in f.name]

            if not instance_files:
                log.error("No instansce files found in subirectory {}".format(scan))
                continue

            scan_outfname = "{}_{}_scan_{}_metadata.txt".format(
                str(compressed_file.name).replace(".tgz", ""),
                exam_id,
                scan.name
            )

            scan_meta = OrderedDict({
                'metadata': {
                    'parent_exam_id': exam_id,
                    'gold_scan_dir': scan.name,
                    'scan_id': scan_id,
                    'num_files': len(instance_files),
                    'parser_version': parser_version,
                },
                'dicom_data': None,
                'private_data': None,
            })

            dicom_instances = [i for i in instance_files if i.name.endswith(".dcm")]

            if not dicom_instances:
                # There are files in the subdirectory, but none of them are DICOM.
                # Save basic metadata about directory
                study_meta['data'].append(scan_meta)
                continue

            # There are dicom instances - try to open at least one of them to get
            # basic metadata for this scan
            sample_file = None
            for dcm_instance in dicom_instances:
                try:
                    sample_file = pydicom.dcmread(str(dcm_instance), stop_before_pixels=True)
                    break
                except InvalidDicomError:
                    log.error("Unable to open invalid DICOM file {}".format(sample_file))
                    sample_file = None

            if not sample_file:
                # None of the DICOM files in subirectory was readable, log an error
                # and add basic subdirectory metadata to study metadata file
                study_meta['data'].append(scan_meta)
                log.error("Unable to open any DICOMs for scan {}".format(scan))
                continue

            else:

                log.info("Found {} DICOM files for scan {} of exam {}".format(
                    len(instance_files),
                    scan.name,
                    exam_dir)
                )

                dicom_data = parse_dicom_dataset(sample_file)

                scan_meta['dicom_data'] = parse_dicom_dataset(sample_file)
                scan_meta['private_data'] = parse_private_data(sample_file)

                study_meta['data'].append(scan_meta)

                collect_ge_extra_meta = False

                try:
                    sop_class = dicom_data['00080016']['Value'][0]
                except (KeyError, IndexError):
                    sop_class = None

                try:
                    manufacturer = dicom_data['00080070']['Value'][0]
                except (KeyError, IndexError):
                    manufacturer = None

                if sop_class and manufacturer:

                    if (sop_class in ["1.2.840.10008.5.1.4.1.1.4", "1.2.840.10008.5.1.4.1.1.4.1"]) and \
                       ("ge" in manufacturer.lower() or "general electric" in manufacturer.lower()):

                        # Determine if series is likely to be multiecho and if so, collect the relevant metadata
                        # to order the scans
                        try:
                            num_indices = dicom_data["00201002"]['Value'][0]
                        except (KeyError, IndexError):
                            num_indices = None

                        try:
                            num_slices = dicom_data["0021104F"]['Value'][0]
                        except (KeyError, IndexError):
                            num_slices = None

                        if not num_indices or not num_slices:
                            log.info("Scan did not have number of slices or number of indices in metadata. Treating"
                                     " as non-multiecho.")
                            continue

                        log.info("Num Indices: {}".format(num_indices))
                        log.info("Num Slices: {}".format(num_slices))

                        if num_indices != num_slices:

                            if num_indices % num_slices != 0:
                                log.warning("Multiecho testing detected possible un-accounted for slices in this "
                                            "acquisition. Treating as a non-multiecho series.")
                                continue

                            num_echoes = num_indices // num_slices

                            log.info("Number of echoes detected: {}".format(num_echoes))

                            # Try to fetch a slice representative slice index - if unable, might be CBV scan
                            try:
                                sample_slice_index = dicom_data['001910A2']['Value'][0]
                            except (KeyError, IndexError):
                                sample_slice_index = None

                            if not sample_slice_index:
                                log.warning("Unable to retrieve slice indices (usually happens with CBV scans), "
                                            "treating as non-multiecho series.")
                                continue

                            # Collect GE metadata for sorting
                            log.info("Scan is probable multiecho - collecting extra metadata for sorting")
                            collect_ge_extra_meta = True

                with open(str(exam_dir / scan_outfname), mode="wt") as outfile:

                    num_workers = 32

                    with ProcessPool(num_workers) as pool:

                        instance_results = []

                        for dcm, dicom_data in pool.imap(
                                get_dicom_meta,
                                [(dcm, collect_ge_extra_meta) for dcm in instance_files]
                        ):

                            instance_results.append("{}\t{}".format(
                                Path(dcm).name,
                                json.dumps(dicom_data)
                            ))

                    outfile.write("\n".join(instance_results))

                log.info("Time elapsed extracting metadata for scan {} of exam {}: {}".format(scan.name, exam_dir,
                                                                                              time.time() - scan_start))

        checksum_start = time.time()

        checksum_cmds = []

        for scan in [d for d in exam_dir.iterdir() if d.is_dir()]:
            # Get checksum for files in scan

            checksum_cmd = "touch {}/{}_{}_scan_{}_checksum.txt " \
                           "&& find . -type f | xargs -I {{}} md5sum {{}} >> {}/{}_{}_scan_{}_checksum.txt".format(
                                str(exam_dir),
                                str(compressed_file.name).replace(".tgz", ""),
                                exam_id,
                                scan.name,
                                str(exam_dir),
                                str(compressed_file.name).replace(".tgz", ""),
                                exam_id,
                                scan.name
                            )

            checksum_cmds.append([checksum_cmd, str(scan)])

        with ProcessPool(16) as pool:

            for msg in pool.imap(get_scan_checksums, checksum_cmds):
                if "Could not" in msg:
                    log.error(msg)
                else:
                    log.info(msg)

        log.info("Time elapsed computing checksums for exam {}: {}".format(exam_dir, time.time() - checksum_start))

        study_outfname = exam_dir / "study_{}_metadata.txt".format(study_meta['metadata']['exam_id'])

        with open(str(study_outfname), "wt") as study_outfile:
            json.dump(study_meta, study_outfile)

        log.info("Removing tmp files...")

        start_rm = time.time()

        for scan_dir in [d for d in exam_dir.iterdir() if d.is_dir()]:
            shutil.rmtree(scan_dir)

        readme_files = [str(f) for f in exam_dir.glob("**/*") if
                        f.is_file() and ("_metadata.txt" not in f.name) and
                        ("_checksum.txt" not in f.name) and ("_filelist.txt" not in f.name)]

        list(map(os.remove, readme_files))

        log.info("Time elapsed removing files from exam {}: {}".format(exam_dir, time.time() - start_rm))

        log.info("Time elapsed extracting metadata from exam {}: {}".format(exam_dir,
                 time.time()-start_extract))


def tgz_extraction(compressed_files, settings):

    if not len(compressed_files) > 0:
        log.error("No compressed files found.")
        return []

    num_workers = settings['tgz_cores']

    log.info("Using {} threads".format(num_workers))

    start_test = time.time()

    extracted_archives = []

    with ThreadPool(num_workers) as pool:

        for success, dat in pool.imap(
                do_full_tgz_extraction,
                [(compressed_file, settings) for compressed_file in compressed_files]
        ):
            if success:
                extracted_archives.append((dat[0], dat[1], dat[2], dat[3]))
            else:
                log.error("Unable to extract archive: {}".format(dat[0]))

    log.info("Total time extracting tgz files: {}".format(time.time() - start_test))

    return extracted_archives


def run_from_cli():

    version = 0.2

    prog_start = time.time()

    parser = argparse.ArgumentParser()

    parser.add_argument("--data_dir", default="/mnt/dicom/download/")

    parser.add_argument("--scanner", default="*")

    parser.add_argument("--year", default="*")

    parser.add_argument("--month", default="*")

    parser.add_argument("--day", default="*")

    parser.add_argument(
        "--work_dir",
        help="Path to working directory",
        default=os.getcwd()
    )

    parser.add_argument(
        "--log",
        help="Log filename. Default: gold2bromine.log",
        default="gold2bromine.log"
    )

    parser.add_argument(
        "--tgz_cores",
        help="Number of cores to use when extracting TGZ files",
        type=int,
        default=12,
    )

    parser.add_argument(
        "--debug",
        help="Log DEBUG messages",
        action='store_true',
    )

    args = parser.parse_args()

    settings = {
        'data_dir': Path(args.data_dir),
        'work_dir': Path(args.work_dir),
        'scanner': args.scanner,
        'year': parse_date(args.year),
        'month': parse_date(args.month),
        'day': parse_date(args.day),
        'tgz_cores': args.tgz_cores,
        'version': version,
        'debug': args.debug,
    }

    log_fpath = Path(os.getcwd()) / args.log

    init_log(log_fpath, debug=args.debug)

    log.info("Data directory: {}".format(settings['data_dir']))
    log.info("Work directory: {}".format(settings['work_dir']))
    log.info("Log location: {}".format(log_fpath))

    log.info("Data selection parameters: ")
    log.info("Scanner: {}".format(settings['scanner']))
    log.info("Year: {}".format(settings['year']))
    log.info("Month: {}".format(settings['month']))
    log.info("Day: {}".format(settings['day']))

    log.info("Searching for compressed Gold archives in data directory...")

    compressed_files = sorted(
        [str(f) for f in settings['data_dir'].glob("{}/{}/{}/{}/*/*.tgz".format(
            settings['scanner'],
            settings['year'],
            settings['month'],
            settings['day'],
        )) if f.is_file()]
    )

    if not (len(compressed_files) > 0):
        log.info("No compressed files found!!!")
        return

    log.info("Found {} compressed files...".format(len(compressed_files)))

    log.info("Extracting the compressed archives...")
    extracted_archives = tgz_extraction(compressed_files, settings)

    if not (len(extracted_archives) > 0):
        log.error("Unable to extract any archive!!!")
        return

    log.info("Extracted {} archives...".format(len(extracted_archives)))

    log.info("Getting exam metadata...")
    start_extract = time.time()
    get_metadata(extracted_archives, parser_version=settings['version'])
    log.info("Total time extracting metadata: {}".format(time.time() - start_extract))

    log.debug("Time elapsed running program: {}".format(time.time()-prog_start))


if __name__ == "__main__":

    run_from_cli()
