from benchmarks.common import measure
from benchmarks.workloads import event
from eye_for_an_eye.fingerprint.ttl import ttl_fingerprint
from eye_for_an_eye.fingerprint.tcp_options import tcp_options
from eye_for_an_eye.fingerprint.ip_id import IpIdTracker
from eye_for_an_eye.fingerprint.tcp_timestamp import TimestampTracker
from eye_for_an_eye.fingerprint.p0f_adapter import P0fAdapter
from eye_for_an_eye.fingerprint.probes import ProbeKey, match_probe
from pathlib import Path
import tempfile


def run(full=False):
    from scapy.layers.inet import TCP, IP, UDP
    header = bytes(TCP(flags='S', options=[('MSS',1460),('Timestamp',(100,0))]))
    ids, stamps = IpIdTracker(), TimestampTracker()
    value = event(1)
    n = 1000 if full else 300
    results = {'ttl': measure(n,lambda i:ttl_fingerprint(51)),
        'tcp_options': measure(n,lambda i:tcp_options(header)),
        'ip_id': measure(n,lambda i:ids.observe('fixture',i,observed_at=i/100)),
        'timestamp': measure(n,lambda i:stamps.observe('fixture',i*100,i/10)),
        'event_serialization': measure(n,lambda i:value.to_json())}
    packet = IP()/TCP(flags='S')
    for name, backend in [('match',lambda p:(('s','unix','fixture','v1'),1,False)),
                           ('no_match',lambda p:None),('fuzzy',lambda p:(('s','unix','fixture','v1'),1,True))]:
        adapter = P0fAdapter(backend=backend)
        results['p0f_adapter_'+name] = measure(n,lambda i:adapter.fingerprint(packet))
    results['p0f_missing_db'] = measure(n,lambda i:P0fAdapter().fingerprint(packet))
    real={}
    with tempfile.TemporaryDirectory() as directory:
        database=Path(directory)/'synthetic.fp'
        database.write_text('[tcp:request]\nlabel = s:unix:Fixture:synthetic\nsig = 4:64:0:0:8192,0::bad:0\n',encoding='ascii')
        adapter=P0fAdapter(database)
        matching=IP(src='192.0.2.1',dst='127.0.0.1',ttl=61,id=1)/TCP(sport=12345,dport=80,seq=1,flags='S',window=8192)
        for name,pkt in (('match',matching),('no_match',IP()/TCP(flags='S',window=1024)),
                         ('df_variant',IP(src='192.0.2.1',dst='127.0.0.1',ttl=61,id=1,flags='DF')/matching[TCP]),
                         ('fuzzy_distance',IP(src='192.0.2.1',dst='127.0.0.1',ttl=20,id=1)/matching[TCP]),
                         ('ack',IP()/TCP(flags='A')),('udp',IP()/UDP())):
            observed=adapter.fingerprint(pkt)
            real[name]={'timing':measure(n,lambda i:adapter.fingerprint(pkt)),
                        'status':observed.status,'fuzzy':observed.fuzzy,'confidence':observed.confidence}
    for count in (16,256,4096):
        probes = {ProbeKey('tcp' if i%2 else 'udp',str(i)):b'FIXTURE-'+str(i).encode() for i in range(count)}
        for size in (32,4096):
            results[f'probe_{count}_payload_{size}'] = measure(80,lambda i:match_probe(b'z'*size,'tcp',probes))
    # One MiB aggregate probe payload budget, matches fail at the last byte.
    for count, size in ((4096,256),(16,65536)):
        probes={ProbeKey('tcp',str(i)):b'x'*(size-1)+b'y' for i in range(count)}
        results[f'probe_adversarial_{count}_{size}']=measure(20,lambda i:match_probe(b'x'*size,'tcp',probes))
    return {'modules':results,'real_scapy_synthetic_database':real,'workload':{'iterations':n,'probe_candidates_transport_fraction':.5,
        'p0f_note':'Adapter contract fixture only. External p0f DB performance not claimed.'}}
