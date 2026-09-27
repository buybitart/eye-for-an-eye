from benchmarks.common import config,measure
from benchmarks.workloads import payloads
from eye_for_an_eye.deception.profiles import PROFILES
from eye_for_an_eye.deception.protocols import ProtocolSession
from eye_for_an_eye.deception.privacy import Privacy
from eye_for_an_eye.deception.selector import select_profile
import gc
import tracemalloc


def run(full=False):
    settings=config()
    privacy=Privacy(bytes(range(32)))
    n=1000 if full else 300
    selection=measure(n,lambda i:select_profile(bytes(range(32)),'192.0.2.100',8000+i%128,'tcp'))
    protocols={}
    for profile in PROFILES:
        totals={'messages':0,'response_bytes':0}
        commands={'http':[b'GET / HTTP/1.0\r\n\r\n'],
                  'ftp':[b'USER fixture\r\n',b'PASS fixture\r\n',b'SYST\r\n',b'PWD\r\n',b'QUIT\r\n'],
                  'ssh':[b'SSH-2.0-Client\r\n']}[profile.service_family]
        def conversation(i):
            session=ProtocolSession(profile,settings.limits,privacy)
            totals['response_bytes']+=sum(len(step.response) for step in session.start())
            for command in commands:
                totals['response_bytes']+=sum(len(step.response) for step in session.feed(command))
                totals['messages']+=1
        protocols[profile.service_family]={'measurement':measure(n,conversation),**totals}
    binary=payloads()[-1]
    profile=PROFILES[-1]
    def malformed(i):
        ProtocolSession(profile,settings.limits,privacy).feed(binary)
    memory={}
    for profile in PROFILES:
        gc.collect()
        tracemalloc.start()
        before=tracemalloc.get_traced_memory()[0]
        sessions=[ProtocolSession(profile,settings.limits,privacy) for _ in range(128)]
        retained,peak=tracemalloc.get_traced_memory()
        memory[profile.profile_id]={'sessions':128,'traced_retained_bytes':retained-before,
            'traced_bytes_per_session_including_list':(retained-before)/128,'peak_bytes':peak}
        tracemalloc.stop()
        del sessions
    return {'hmac_selection':selection,'protocols':protocols,'binary_parser':measure(n,malformed),
            'session_memory':memory,
            'workload':{'conversations_per_protocol':n,'catalogue_version':2,'bytes_secret':'public test fixture'}}
