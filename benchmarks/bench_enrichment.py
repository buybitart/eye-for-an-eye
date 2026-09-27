import threading
import time
from benchmarks.common import config,configuration,measure,resources
from benchmarks.workloads import event
from eye_for_an_eye.enrichment.worker import EnrichmentService
from eye_for_an_eye.events import EventPipeline
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime


def provider(ip,options):
    if options.get('scenario')=='slow':
        time.sleep(.1)
    elif options.get('scenario')=='timeout':
        time.sleep(2)
    return {'status':'unavailable' if options.get('scenario')=='unavailable' else 'ok'}


def run(full=False):
    rows={}
    for scenario in ('ok','slow','timeout','unavailable'):
        settings=config()
        settings.correlation.enabled=False
        runtime=EventRuntime(settings,logger=EventLogger(settings.logging,writer=lambda line:None))
        completed=threading.Event()
        pipeline=EventPipeline(runtime)
        def result(event_id,ip,value):
            pipeline.enriched(event_id,ip,value)
            completed.set()
        service=EnrichmentService(provider=provider,on_result=result,enabled=True,workers=1,queue_size=4,
            timeout=.4,provider_options={'scenario':scenario})
        runtime.attach(enrichment=service)
        runtime.start()
        service.start()
        before=resources()
        try:
            submit=measure(12,lambda i:service.submit(str(i),f'192.0.2.{i+1}'))
            core=measure(200,lambda i:runtime.emit(event(i)))
            completed.wait(1)
            # Explicitly warm the bounded cache from actual completed provider result.
            cache=measure(30,lambda i:service.submit('hit-'+str(i),'192.0.2.1'))
            rows[scenario]={'submit':submit,'core_emit':core,'warm_or_negative_cache':cache,
                'metrics':dict(service.metrics),'queue_depth':service.queue.qsize(),
                'active_provider_processes':service.active_processes,'cache':service.cache.metrics,
                'resources_before':before,'resources_during':resources()}
        finally:
            service.close()
            runtime.close()
        rows[scenario]['resources_after']=resources()
    return {'configuration':configuration(settings),'scenarios':rows,'provider':'local fixture only; no RDAP/DNS/Internet','worker_limit':1,
        'queue_limit':4,'provider_timeout_seconds':.4,'note':'spawn cost included; queue_full and backoff are expected'}
