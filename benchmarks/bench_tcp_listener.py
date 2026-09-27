import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from benchmarks.common import config,configuration,measure,resources,percentiles
from eye_for_an_eye.network.listeners import SelectorServer


def run(full=False):
    settings=config()
    settings.limits.max_connections=settings.limits.max_connections_per_ip=128
    settings.limits.connections_per_second=1000
    settings.limits.first_byte_timeout=.7
    settings.limits.idle_timeout=.35
    settings.limits.total_timeout=1.2
    before=resources()
    server=SelectorServer(settings,on_data=lambda peer,dst,data:b'OK\n' if data.endswith(b'\n') else b'',port=0,max_duration=25)
    thread=threading.Thread(target=server.serve_forever)
    thread.start()
    if not server.ready.wait(2) or server.error:
        raise RuntimeError('local listener startup')
    def request(i=0):
        with socket.create_connection(server.address,timeout=2) as client:
            client.sendall(b'fixture\n')
            if client.recv(32)!=b'OK\n':
                raise RuntimeError('listener response')
    stages={}
    idle=[]
    try:
        request()
        stages['normal_10_per_second']=measure(10,lambda i:(request(),time.sleep(.1)))
        stages['fast']=measure(300 if full else 100,request)
        latencies=[]
        def parallel(i):
            stamp=time.perf_counter()
            request(i)
            return (time.perf_counter()-stamp)*1000
        started=time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as pool:
            latencies=list(pool.map(parallel,range(200)))
        stages['parallel_8']={'connections':200,'seconds':time.perf_counter()-started,**percentiles(latencies)}
        for target in (10,100,128):
            warm=resources()
            for _ in range(target):
                idle.append(socket.create_connection(server.address,timeout=1))
            until=time.monotonic()+.3
            while server.active_connections<target and time.monotonic()<until:
                time.sleep(.005)
            current=resources()
            second=measure(1,request) if target<128 else {'result':'at configured cap; additional connection intentionally not opened'}
            stages[f'idle_{target}']={'active':server.active_connections,'before':warm,'during':current,
                'rss_delta_per_connection':(current['rss_bytes']-warm['rss_bytes'])/target,'second_client':second}
            for client in idle:
                client.close()
            idle.clear()
            until=time.monotonic()+1
            while server.active_connections and time.monotonic()<until:
                time.sleep(.005)
        slow=socket.create_connection(server.address,timeout=2)
        slow_started=time.perf_counter()
        sends=0
        concurrent=[]
        try:
            for _ in range(20):
                try:
                    slow.sendall(b'x')
                    sends+=1
                    if sends in (2, 5, 8):
                        concurrent.append(measure(1,request))
                    time.sleep(.08)
                    slow.settimeout(.001)
                    if slow.recv(1)==b'':
                        break
                except socket.timeout:
                    pass
                except (ConnectionResetError,BrokenPipeError,ConnectionAbortedError):
                    break
                if time.perf_counter()-slow_started>1.6:
                    break
            stages['slow_client']={'bytes_sent':sends,'lifetime_seconds':time.perf_counter()-slow_started,
                'configured_total_timeout':settings.limits.total_timeout,'second_client':measure(3,request),
                'second_client_while_slow_active':concurrent}
        finally:
            slow.close()
        # Open finite maximum and measure teardown while sockets remain active.
        idle=[socket.create_connection(server.address,timeout=1) for _ in range(128)]
    finally:
        started=time.perf_counter()
        server.stop()
        thread.join(2)
        for client in idle:
            client.close()
        shutdown=time.perf_counter()-started
    if thread.is_alive() or server.error:
        raise RuntimeError('listener shutdown')
    return {'configuration':configuration(settings),'workload':{'bind':'127.0.0.1','maximum_active':128,'parallel_workers':8},
        'stages':stages,'listener_metrics':dict(server.metrics),'resources_before':before,'resources_after':resources(),
        'shutdown_seconds':shutdown,'limitations':['Windows selector cap conservatively 128; 500/1000 not attempted',
        'normal workload includes intentional pacing','RSS includes generator sockets in same process']}
