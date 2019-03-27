import json
import os
import glob

CORPUS_DB_VERSION = 1

def check(testcase):
    # TODO
    return True

def db_open(dir):
    corpus_db = {
        'version':CORPUS_DB_VERSION,
        'testcases':[]
    }

    if not os.path.exists(dir):
        os.mkdir(dir)
        return corpus_db

    for file in glob.glob(os.path.join(dir,'*.json')):
        testcase = json.load(open(file))
        if check(testcase):
            corpus_db['testcases'].append(testcase)

    return corpus_db
