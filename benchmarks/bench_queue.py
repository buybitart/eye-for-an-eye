import time
from benchmarks.common import config,measure
from benchmarks.workloads import event
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.event_types import EventType


def run(full=False):
    settings=config()
    settings.runtime.queue_events=64
    settings.runtime.queue_bytes=65536
    runtime=EventRuntime(settings,logger=EventLogger(settings.logging,writer=lambda line:None))
    # Consumer deliberately absent during finite burst: exact drop threshold.
    producer=measure(300,lambda i:runtime.emit(event(i)))
    saturated=runtime.queue.snapshot()
    started=time.perf_counter()
    runtime.start()
    closed=runtime.close()
    drain=time.perf_counter()-started
    settings.runtime.load_shedding=True
    prioritized=EventRuntime(settings,logger=EventLogger(settings.logging,writer=lambda line:None))
    types=(EventType.CONNECTION_CLOSED,EventType.CONNECTION_ACCEPTED,EventType.RUNTIME_WARNING)
    outcomes={}
    for kind in types:
        accepted=0
        for index in range(64):
            value=event(index)
            value.event_type=kind
            accepted+=prioritized.emit(value)
        outcomes[kind]=accepted
    priority_state=prioritized.snapshot()
    prioritized.start()
    priority_closed=prioritized.close()
    return {'producer':producer,'saturated':saturated,'after':runtime.snapshot(),'drain_shutdown_seconds':drain,
            'priority_admitted':outcomes,'priority_saturated':priority_state,'priority_closed':priority_closed,
            'closed':closed,'workload':{'producer_events':300,'consumer_delayed':True,'queue_events':64,'queue_bytes':65536}}
