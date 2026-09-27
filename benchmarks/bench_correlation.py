import gc
from benchmarks.common import config, configuration, measure, resources
from benchmarks.workloads import event
from eye_for_an_eye.correlation.engine import CorrelationEngine


def run(full=False):
    settings = config()
    engine = CorrelationEngine(settings.correlation)
    scanner = measure(1000 if full else 300,lambda i:engine.observe(event(i,4)))
    del engine
    gc.collect()
    engine = CorrelationEngine(settings.correlation)
    points = [100,1000,10000,50000,100000] if full else [100,1000]
    rows, previous = [], 0
    for count in points:
        before = resources()
        timing = measure(count-previous,lambda i:engine.observe(event(previous+i,50000)))
        row = {'input_events':count,'distinct_input_sources':min(count,50000),'measurement':timing,
               'state':engine.snapshot(),'rss':resources()['rss_bytes'],'rss_start_segment':before['rss_bytes']}
        rows.append(row)
        previous = count
    rotation = measure(100,lambda i:engine.observe(event(100001+i,50000,stamp=2000+i/100)))
    return {'configuration':configuration(settings),'scanner':scanner,'source_pressure':rows,
            'expiration_window_rotation':rotation,'final_state':engine.snapshot(),
            'limits_note':'Configured 10000 sources/32MiB accounted state; 50000 identities are offline metadata only.'}
