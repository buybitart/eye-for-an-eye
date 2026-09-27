from dataclasses import replace
import json
from pathlib import Path
import tempfile
import time
from benchmarks.common import config,configuration,measure,percentiles
from benchmarks.workloads import event
from eye_for_an_eye.events import NetworkEvent
from eye_for_an_eye.storage.sqlite import SQLiteStore


def candidate(store, events, batch):
    latencies=[]
    started=time.perf_counter()
    for offset in range(0,len(events),batch):
        stamp=time.perf_counter()
        store.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        if not store._space_for_transaction():
            raise RuntimeError('candidate disk budget')
        store.connection.execute('BEGIN IMMEDIATE')
        store._cleanup(store.config.max_events-batch)
        for value in events[offset:offset+batch]:
            data=value.to_json()
            value=NetworkEvent.from_json(data)
            store.connection.execute('INSERT INTO events(event_id,ingested_at,sensor_id,event_type,event_json,'
                'observed_at,src_ip,src_port,dst_ip,dst_port,transport,classification,confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (value.event_id,time.time(),value.sensor_id,value.event_type,data,*store._columns(value)))
        store.connection.execute('COMMIT')
        store.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        latencies.append((time.perf_counter()-stamp)*1000)
    elapsed=time.perf_counter()-started
    return {'rows':len(events),'batch':batch,'seconds':elapsed,'rows_per_second':len(events)/elapsed,
            'transaction_latency':percentiles(latencies),'disk_bytes':store.disk_bytes(),
            'scope':'benchmark-only SQL experiment; retention/error/retry behavior not a production replacement'}


def run(full=False):
    settings=config()
    n=300 if full else 100
    rows=[event(i) for i in range(n)]
    with tempfile.TemporaryDirectory() as directory:
        store=SQLiteStore(replace(settings.storage,path=str(Path(directory)/'production.db')))
        store.open()
        try:
            production=measure(n,lambda i:store.write(rows[i]))
            disk=store.disk_bytes()
        finally:
            store.close()
        production_batches={}
        for batch in (8,32):
            store=SQLiteStore(replace(settings.storage,path=str(Path(directory)/f'production-{batch}.db'),max_batch_events=batch))
            store.open()
            try:
                def write_batch(i):
                    if not all(store.write_batch(rows[i*batch:(i+1)*batch])):
                        raise RuntimeError('production batch rejected')
                result=measure((n+batch-1)//batch,write_batch)
                result.update(rows=n,rows_per_second=n/result['seconds'],disk_bytes=store.disk_bytes(),metrics=dict(store.metrics))
                production_batches[str(batch)]=result
            finally:
                store.close()
        variants={}
        for batch in (1,8,32):
            store=SQLiteStore(replace(settings.storage,path=str(Path(directory)/f'batch-{batch}.db')))
            store.open()
            try:
                variants[str(batch)]=candidate(store,rows,batch)
            finally:
                store.close()
    return {'configuration':configuration(settings),'production_single':production,'production_batches':production_batches,'disk_bytes':disk,'SQL_candidates':variants,
            'serialized_bytes':sum(len(row.to_json()) for row in rows),'serialization':measure(n,lambda i:json.dumps(rows[i].to_dict()))}
