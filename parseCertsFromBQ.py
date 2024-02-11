import base64
import datetime
import fnmatch
import functools
import json
import multiprocessing
import sys
from multiprocessing import Pool

import multiprocessing_logging
import ujson
from pprint import pprint
from typing import List

import msgpack as msgpack
import pandas as pd
import datetime as dt
import time
import tqdm
import requests
import random
import os
import typing
import logging
from multiprocessing import Pool

if typing.TYPE_CHECKING:
    from google.cloud import bigquery


import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

import googleapiclient.discovery  # type: ignore

###########################################
# EKKI BREYTA NEINU HÉR
# þessi kóði ætti ekki að vera keyrður aftur
###########################################

SCOPES = ["https://www.googleapis.com/auth/bigquery.readonly"]
PROJECT_ID = "censys-402109"


def get_client() -> "bigquery.Client":
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                '/home/mha/PycharmProjects/thesis/bigQueryCode/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # key_path = ".creds.json"
    #
    # # [START bigquery_client_json_credentials]
    from google.cloud import bigquery
    # from google.oauth2 import service_account
    #
    # # TODO(developer): Set key_path to the path to the service account key
    # #                  file.
    # # key_path = "path/to/service_account.json"
    #
    # credentials = service_account.Credentials.from_service_account_file(
    #     key_path,
    #     scopes=["https://www.googleapis.com/auth/bigquery.readonly",
    #             "https://www.googleapis.com/auth/bigquery"],
    # )

    # Alternatively, use service_account.Credentials.from_service_account_info()
    # to set credentials directly via a json object rather than set a filepath
    # TODO(developer): Set key_json to the content of the service account key file.
    # credentials = service_account.Credentials.from_service_account_info(key_json)

    client = bigquery.Client(
        credentials=creds,
        project=PROJECT_ID,
    )
    # [END bigquery_client_json_credentials]
    return client


def clean_block_list():
    phish = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/bigQueryCode/phishtank.csv', sep=',',
                        header=0)
    phish['verification_time'] = pd.to_datetime(phish['verification_time'])
    phish = phish[phish['verification_time'].dt.year == 2023]
    phish[['protocol', 'urlNoProto']] = phish['url'].str.split('://', expand=True, n=1)
    phish = phish.drop(phish[phish.protocol == "http"].index)
    phish.reset_index(inplace=True)
    phish[['fullDomain', 'path']] = phish['urlNoProto'].str.split('/', expand=True, n=1)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('google.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('amazonaws.com')].index)
    phish = phish.drop(phish[phish['fullDomain'].str.endswith('googleapis.com')].index)
    phish.reset_index(inplace=True)
    phish['fullDomain'] = phish['fullDomain'].str.replace('www.', '')
    return phish


def top_tranco():
    tranco_raw = pd.read_csv(filepath_or_buffer='/home/mha/PycharmProjects/thesis/bigQueryCode/tranco.csv', sep=',',
                             header=0)
    return tranco_raw.drop(tranco_raw[tranco_raw['rank'] > 20000].index)


def create_match_set():
    tranco = top_tranco()
    block_list = clean_block_list()
    s = set(tranco['domain'].unique())
    s.update(block_list['fullDomain'].unique())

    keep_domains = dict()
    for domain in s:
        add_keep_domain(domain, keep_domains)
    return keep_domains


def create_tranco_set():
    tranco = top_tranco()
    s = set(tranco['domain'].unique())

    keep_domains = dict()
    for domain in s:
        add_keep_domain(domain, keep_domains)
    return keep_domains




def bool_cast(s):
    return s == "true"


def bytes_cast(s):
    return base64.decodebytes(s.encode())


def timestamp_cast(s):
    return float(s)


def convert_recur(projection, schema, ignore_repeated=False):
    if schema["mode"] == "REPEATED" and not ignore_repeated:
        return [convert_recur(p['v'] if 'v' in p else p, schema, ignore_repeated=True) for p in projection]

    if (ignore_repeated or schema["mode"] == "NULLABLE") and projection is None:
        return None

    if schema["type"] == "RECORD":
        return dict((f['name'], convert_recur(p['v'], f)) for (f, p) in zip(schema['fields'], projection['f']))

    if schema["type"] == "INTEGER":
        cast = int
    elif schema["type"] == "STRING":
        cast = str
    elif schema["type"] == "BYTES":
        cast = bytes_cast
    elif schema["type"] == "BOOLEAN":
        cast = bool_cast
    elif schema["type"] == "TIMESTAMP":
        cast = timestamp_cast
    else:
        raise NotImplementedError(f"no cast defined for type {schema['type']}")

    return cast(projection)


def gen_filtered_rows(rows, filt):
    for row in rows:
        if filt(row):
            yield row


def add_keep_domain(domain: str, keep_domains: dict):
    reversed_parts = reversed(domain.split('.'))
    domain_node = keep_domains
    for part in reversed_parts:
        try:
            domain_node = domain_node[part]
        except KeyError:
            n_domain_node = dict()
            domain_node[part] = n_domain_node
            domain_node = n_domain_node

    domain_node["."] = domain


def is_in_keep_domains(domain: str, keep_domains: dict):
    reversed_parts = reversed(domain.split('.'))
    domain_node = keep_domains
    for part in reversed_parts:
        try:
            domain_node = domain_node[part]
        except KeyError:
            if part == '*':
                for domain, subdomains in domain_node.items():
                    if domain == '.':
                        continue
                    if '.' in subdomains:
                        return True
            return False

    return '.' in domain_node


class Filter:
    def __init__(self, keep_names=None):
        self.keep_names = create_match_set() if keep_names is None else keep_names
        self.prob = 0.00001

    def __call__(self, row):
        for name in row["f"][0]["v"]:
            if is_in_keep_domains(name['v'], self.keep_names):
                return True
        if random.random() < self.prob:
            return True
        return False


PROJECT = "censys-402109"
JOB_ID = "bquxjob_3248bb2b_18ba8d66145"


def call_bq_api(client: "bigquery.Client", page_token, block_i, block_sz, remaining):
    start_index = block_i * block_sz

    path = "/projects/{}/queries/{}".format(PROJECT, JOB_ID)

    extra_params = dict(
        location="US",
        maxResults=remaining

    )
    if page_token:
        extra_params['pageToken'] = page_token
    else:
        extra_params['startIndex'] = start_index

    span_attributes = dict(
        path=path,
    )

    return client._call_api(
        None,
        span_name="BigQuery.getQueryResults",
        span_attributes=span_attributes,
        method="GET",
        path=path,
        query_params=extra_params,
        timeout=60 * 12,
    )



class MultiProcessingHandler(multiprocessing_logging.MultiProcessingHandler):
    def __get_state__(self):
        state = self.__dict__.copy()
        del state['_receive_thread']
        del state['sub_handler']
        return state

    def __setstate__(self, state):
        # Restore instance attributes (i.e., filename and lineno).
        self.__dict__.update(state)

    def __reduce__(self):
        return super().__reduce__()


def install_mp_handler(logger=None):
    """Wraps the handlers in the given Logger with an MultiProcessingHandler.

    :param logger: whose handlers to wrap. By default, the root logger.
    """
    if logger is None:
        logger = logging.getLogger()

    for i, orig_handler in enumerate(list(logger.handlers)):
        handler = MultiProcessingHandler("mp-handler-{0}".format(i), sub_handler=orig_handler)

        logger.removeHandler(orig_handler)
        logger.addHandler(handler)


LOG_Q = multiprocessing.Manager().Queue()


def get_results_for_block(logger, keep_names: dict, blocksize: int, blocknumber: int):
    try:
        # logging.basicConfig(format=LOG_FORMAT, force=True)
        # install_slave_handler(logQueue)
        # print(f'filter has {len(filt.keep_names)} keep names')
        if os.path.exists(f"bigQueryOutputs/output_{blocknumber}_{blocksize}_DONE"):
            logger.info(f"Nothing to do for block {blocknumber}")
            return
        filt = Filter(keep_names)
        client = get_client()
        # start_time = time.time()
        counter = 0
        # print("Call " + str(counter))
        api_call_time = time.time()
        remaining_rows = blocksize
        results = call_bq_api(client,
                              None,
                              block_i=blocknumber,
                              block_sz=blocksize,
                              remaining=remaining_rows,
                              )
        if results.get("rows") is None:
            with open(f"bigQueryOutputs/output_{blocknumber}_{blocksize}_DONE", 'w') as fp:
                fp.write("DONE")
                logger.info(f"No Data: completed {fp.name}")
            return

        logger.info("--- API call time %s seconds ---" % (time.time() - api_call_time))
        # print("Number of rows " + str(len(results.get('rows'))))

        # with open("bigQueryApiNewSchema.json", 'r') as fp:
        #     results = ujson.load(fp)
        page_token = results.get('pageToken', None)

        counter = 0
        # filtered_rows_total = len(results.get('rows'))
        # print("Call " + str(counter))
        # print("Number of rows " + str(len(results.get('rows'))))
        while page_token != '':
            root_schema = results['schema']
            root_schema['type'] = 'RECORD'
            root_schema['mode'] = 'REPEATED'
            root_schema['name'] = 'root'
            # pprint(convert_recur(gen_filtered_rows(results['rows'], filt), root_schema))
            # break
            with open(f"bigQueryOutputs/output_{blocknumber}_{counter}_{blocksize}.mp", 'wb') as fp_out:
                msgpack.dump(convert_recur(gen_filtered_rows(results['rows'], filt), root_schema), fp_out)
                # print(f"completed {fp_out.name}")
                logger.info(f"Block {blocknumber} iteration {counter} filtered {len(results.get('rows'))}")

            # print("--- %s seconds ---" % (time.time() - start_time))
            # start_time = time.time()
            remaining_rows -= len(results.get('rows'))
            if not page_token or remaining_rows <= 0:
                break

            counter = counter + 1
            # print("Call " + str(counter))
            api_call_time = time.time()
            for i in range(3):
                try:
                    results = call_bq_api(client, page_token, block_i=blocknumber,
                                      block_sz=blocksize, remaining=remaining_rows)
                except Exception as e:
                    if i < 3:
                        logger.error(f"Failed API call for block {blocknumber} call number {counter}", exc_info = e)
                    else:
                        logger.error(f"Failed all 3 attempts for block {blocknumber} call number {counter}", exc_info = e)
                        raise

            # filtered_rows_total += len(results.get('rows'))
            logger.info("--- API call time %s seconds ---" % (time.time() - api_call_time))
            page_token = results.get('pageToken', None)
            # with open("latestPageToken.txt", 'w') as fp_out:
            #     fp_out.write(page_token)
            # logging.info("Number of rows " + str(len(results.get('rows'))))

        with open(f"bigQueryOutputs/output_{blocknumber}_{blocksize}_DONE", 'w') as fp:
            fp.write("DONE")
            logger.info(f"completed {fp.name}")
    except Exception as e:
        logger.error(f"Unhandled Error in block {blocknumber}", exc_info=e)
        return


def main():
    # logger = logging.getLogger()
    logging.basicConfig(filename='parse_certs.log',
                        format='[%(process)s][%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s'
                        , level=logging.DEBUG)
    install_mp_handler()

    block_size = int(sys.argv[1])
    total_blocks = int(sys.argv[2])
    n_workers = int(sys.argv[3])
    filt = Filter()

    block_numbers = list(range(0, total_blocks))
    block_numbers_left = [i for i in block_numbers if not os.path.exists(f"bigQueryOutputs/output_{i}_{block_size}_DONE")]
    # block_numbers_left.reverse()

    f = functools.partial(get_results_for_block, logging.getLogger(), filt.keep_names, block_size)
    with tqdm.tqdm(total=total_blocks) as pbar:
        pbar.update(len(block_numbers) - len(block_numbers_left))
        with Pool(n_workers) as p:
            for _ in p.imap_unordered(f, block_numbers_left):
                pbar.update(1)


if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
