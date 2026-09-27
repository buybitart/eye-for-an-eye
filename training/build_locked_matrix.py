"""Derive the P15.4 locked matrix from the development one.

Same behaviours, same sites, same profiles. The **benign side is not trimmed**:
the release gate asks for at least 500 distinct benign sources before a
false-block rate means anything, and P15.3 learned what happens when a corpus
falls below that — the gate cannot be evaluated at all, which is a worse outcome
than a disappointing number. So the room for the two withheld families is taken
from the malicious side, which has far more than the 50 sources the gate needs.

Written as a script and committed alongside its output, so the locked matrix is
a file a reviewer can read rather than something conjured at scoring time.
"""
import pathlib
import re

from dataset.scenarios import REGISTRY, load

HEADER = '''# dataset-p15-4-locked-v1: the P15.4 locked benchmark.
#
# SCORED EXACTLY ONCE, after the freeze commit. If it fails, the candidate
# fails: no weight, threshold, gate, feature or calibrator is changed and the
# test rerun.
#
# Derived from `matrix-p15-4-dev-v1.toml` by `_mklocked.py` -- the same
# behaviours, the same nine sites, the same five profiles -- plus the two
# families that appear in no fitting corpus at all:
#
#   withheld/mobile-app-sync   an app waking, retrying a dropped connection and
#                              authenticating on every call, a third of whose
#                              outcomes the sensor genuinely cannot observe
#   withheld/probe-then-login  a six-port sweep followed by nine refused logins,
#                              where neither half reaches anything alone
#
# Those two are the generalisation claim. Everything else is a fresh draw of
# behaviour this cycle has seen, which measures stability under different random
# draws and different source addresses and measures nothing about
# generalisation. The distinction is stated because a benchmark that blurs it
# reports one number and is read as the other.
#
# The benign side is unchanged from the development matrix, deliberately: the
# release gate needs at least 500 distinct benign sources before a false-block
# rate means anything, and a corpus below that cannot be evaluated at all. The
# room for the withheld families came off the malicious side, which has several
# times the 50 sources the gate asks for.
#
# `tests/test_p15_4_withheld.py` fails if either withheld family appears in a
# fitting matrix, and `dataset/split.py` holds both out of training as well.
# Getting this wrong produces a number that is quietly meaningless rather than
# obviously broken, so it is guarded twice.
#
# A different seed salt from every other corpus, so the source addresses and
# every random draw differ from the development and calibration sets.

'''

WITHHELD = '''

# --- withheld from every fitting corpus (§49, §50) --------------------------
# The only two families here that no threshold, no interaction term, no feature
# and no calibrator has ever seen. Scored once, with everything above them
# frozen.

[[scenario]]
id = "withheld/mobile-app-sync"
group = "withheld-mobile-sync"
generator = "withheld.mobile_app_sync"
runs = 18
params = { wakes = 6, calls = 7 }
site_group = "site-api-1"
profile_type = "api"

[[scenario]]
id = "withheld/probe-then-login"
group = "withheld-probe-login"
generator = "withheld.probe_then_login"
runs = 14
params = { ports = 6, failures = 9 }
site_group = "site-web-2"
profile_type = "public_website"
'''

#: Malicious runs after trimming. Chosen so the whole matrix fits inside the
#: 762-address documentation pool with room to spare, and so far above the
#: gate's minimum of 50 that the trim cannot affect whether a gate can be
#: evaluated.
MALICIOUS_TARGET = 190


def labels_by_scenario(path):
    matrix = load(path)
    out = {}
    for entry in matrix['scenario']:
        plan = REGISTRY[entry['generator']](entry['id'], entry['group'], 'label-probe',
                                            **entry.get('params', {}))
        out[entry['id']] = plan.label
    return out


def main():
    source = pathlib.Path('dataset/scenarios/matrix-p15-4-dev-v1.toml')
    labels = labels_by_scenario(source)
    text = source.read_text(encoding='utf-8')
    body = 'matrix_version' + text.split('matrix_version', 1)[1]
    malicious_total = sum(
        int(re.search(r'runs = (\d+)', block).group(1))
        for block in body.split('[[scenario]]')[1:]
        if labels[re.search(r'id = "([^"]+)"', block).group(1)] == 'malicious_automation_like')
    factor = MALICIOUS_TARGET / malicious_total

    blocks = body.split('[[scenario]]')
    rebuilt = [blocks[0]]
    for block in blocks[1:]:
        scenario = re.search(r'id = "([^"]+)"', block).group(1)
        if labels[scenario] == 'malicious_automation_like':
            block = re.sub(r'runs = (\d+)',
                           lambda m: 'runs = ' + str(max(4, round(int(m.group(1)) * factor))),
                           block, count=1)
        rebuilt.append(block)
    body = '[[scenario]]'.join(rebuilt)
    body = body.replace('dataset_version = "dataset-p15-4-dev-v1"',
                        'dataset_version = "dataset-p15-4-locked-v1"')
    target = pathlib.Path('dataset/scenarios/matrix-p15-4-locked-v1.toml')
    target.write_text(HEADER + body.rstrip('\n') + WITHHELD, encoding='utf-8')

    matrix = load(target)
    counts = {'benign_like': 0, 'malicious_automation_like': 0}
    for entry in matrix['scenario']:
        plan = REGISTRY[entry['generator']](entry['id'], entry['group'], 'label-probe',
                                            **entry.get('params', {}))
        counts[plan.label] += entry['runs']
    print('locked matrix:', counts, 'total', sum(counts.values()),
          'scenarios', len(matrix['scenario']))


if __name__ == '__main__':
    main()
