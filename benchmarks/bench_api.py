from datetime import datetime,timezone
import http.client
from pathlib import Path
import socket
import tempfile
import threading
import time
from benchmarks.common import config,configuration,measure,percentiles
from benchmarks.workloads import event
from eye_for_an_eye.logging import EventLogger
from eye_for_an_eye.runtime import EventRuntime
from eye_for_an_eye.storage.reader import Reader,Query


def free_port():
    with socket.socket() as value:
        value.bind(('127.0.0.1',0))
        return value.getsockname()[1]


def run(full=False):
    settings=config()
    settings.api.enabled=True
    settings.api.port=free_port()
    settings.api.requests_per_second=1000
    settings.storage.enabled=True
    n=1000 if full else 250
    with tempfile.TemporaryDirectory() as directory:
        settings.storage.path=str(Path(directory)/'api.db')
        runtime=EventRuntime(settings,logger=EventLogger(settings.logging,writer=lambda line:None))
        runtime.start()
        def write(index):
            value=event(index)
            value.timestamp=datetime.now(timezone.utc)
            return runtime.emit(value)
        for index in range(n):
            write(index)
        deadline=time.monotonic()+15
        while (not runtime.queue.empty() or runtime.storage_started) and time.monotonic()<deadline:
            time.sleep(.01)
        if not runtime.queue.empty():
            raise RuntimeError('API seed drain budget')
        response_bytes={}
        def get(path):
            conn=http.client.HTTPConnection('127.0.0.1',settings.api.port,timeout=2)
            try:
                conn.request('GET',path)
                response=conn.getresponse()
                body=response.read(65537)
                if response.status!=200 or len(body)>65536:
                    raise RuntimeError('bounded API query failed')
                response_bytes[path]=max(response_bytes.get(path,0),len(body))
            finally:
                conn.close()
        routes=('/health','/api/v1/events?limit=20','/api/v1/sources?limit=20','/api/v1/detections?limit=20','/api/v1/stats')
        try:
            results={path:measure(20,lambda i:get(path)) for path in routes}
            running=threading.Event()
            running.set()
            def producer():
                for index in range(n,n+200):
                    if not running.is_set():
                        break
                    write(index)
                    time.sleep(.005)
            thread=threading.Thread(target=producer)
            thread.start()
            lat=[]
            for index in range(60):
                started=time.perf_counter()
                get(routes[index%len(routes)])
                lat.append((time.perf_counter()-started)*1000)
            thread.join(3)
            running.clear()
            if thread.is_alive():
                raise RuntimeError('producer shutdown')
            reader=Reader(settings.storage.path,settings.api)
            query=Query.parse({'limit':'20'},settings.api)
            read_timing=measure(20,lambda i:reader.events(query))
            index,where,args=reader.where(query)
            with reader.connect() as connection:
                plan=connection.execute(f'EXPLAIN QUERY PLAN SELECT seq,event_json FROM events INDEXED BY {index} WHERE {where} ORDER BY seq DESC LIMIT ?',(*args,21)).fetchall()
            state=runtime.snapshot()
        finally:
            if not runtime.close():
                raise RuntimeError('API runtime shutdown')
    return {'configuration':configuration(settings),'seed_events':n,'routes':results,'response_bytes':response_bytes,
        'under_writes':percentiles(lat),'read_connection_query_decode':read_timing,'query_plan':plan,
        'metrics':state['metrics'],'queue':state['queue'],'pagination':'seq keyset; no OFFSET'}
