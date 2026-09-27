from benchmarks.common import measure,resources
from eye_for_an_eye.enrichment.cache import TTLCache
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.observability.metrics import Metrics
from benchmarks.workloads import event
from benchmarks.common import config


def run(full=False):
    now=[0.]
    cache=TTLCache(1000,10,clock=lambda:now[0],max_bytes=4194304)
    cold=measure(1000,lambda i:cache.set(i,{'value':i}))
    warm=measure(1000,lambda i:cache.get(i))
    churn=measure(5000 if full else 1000,lambda i:cache.set(i+1000,{'value':i}))
    now[0]=11
    expiry=measure(1,lambda i:len(cache))
    cache.set('negative',{'status':'unavailable'})
    negative=measure(1000,lambda i:cache.get('negative'))
    metrics=Metrics()
    counters=measure(10000,lambda i:metrics.inc('events_created_total'))
    histograms=measure(10000,lambda i:metrics.observe('handler_duration_seconds',.001))
    scrape=measure(200,lambda i:metrics.prometheus())
    settings=config()
    logger=EventLogger(settings.logging,writer=lambda line:None)
    value=event(0)
    logging=measure(1000,lambda i:logger.emit(value))
    normal=EventLogger(settings.logging,writer=lambda line:None)
    normal.start()
    try:
        normal_logging=measure(10,lambda i:normal.emit(event(i)))
    finally:
        normal.close()
    return {'cold':cold,'warm':warm,'churn':churn,'expiration_storm':expiry,'negative':negative,
        'cache_metrics':cache.metrics,'cache_bytes':cache.current_bytes,'metrics_counter':counters,
        'metrics_scrape':scrape,'metrics_histogram':histograms,'metrics_series':len(metrics.snapshot()),
        'logging_info_normal':normal_logging,'logging_attack_sampled':logging,
        'logging_counters':dict(logger.metrics),'resources':resources(),
        'logging_note':'INFO only, no DEBUG runtime mode. Bounded queue and sampling enabled.'}
