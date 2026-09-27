"""Run each scenario in a bounded child. No performance assertion in normal CI."""
import argparse
import cProfile
import importlib
import json
from pathlib import Path
import pstats
from benchmarks.common import environment,guarded,configuration,config

CASES=('packet_parsing','fingerprinting','correlation','cache','deception','storage','tcp_listener','api','api_large','enrichment','queue','lifecycle','autonomous')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--case',choices=CASES,required=True)
    parser.add_argument('--full',action='store_true')
    parser.add_argument('--profile',action='store_true')
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.worker:
        module=importlib.import_module('benchmarks.bench_'+args.case)
        profile=cProfile.Profile()
        if args.profile:
            profile.enable()
        result=module.run(args.full)
        result.setdefault('configuration',configuration(config()))
        if args.profile:
            profile.disable()
            stats=pstats.Stats(profile)
            rows=[{'file':Path(key[0]).name,'line':key[1],'function':key[2],'calls':value[1],
                   'self_seconds':value[2],'cumulative_seconds':value[3]} for key,value in stats.stats.items()]
            result['profile_top_cumulative']=sorted(rows,key=lambda item:item['cumulative_seconds'],reverse=True)[:30]
            result['profile_top_self']=sorted(rows,key=lambda item:item['self_seconds'],reverse=True)[:30]
        print(json.dumps({'environment':environment(),'case':args.case,'full':args.full,'profiled':args.profile,'data':result}))
        return
    argv=['-m','benchmarks.run','--worker','--case',args.case]
    if args.full:
        argv.append('--full')
    if args.profile:
        argv.append('--profile')
    result=guarded(argv,wall=180,cpu=150)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    data=result['result']
    print(json.dumps({'case':args.case,'source_sha256':data['environment']['source_sha256'],
                      'result_path':str(args.output),'data':data['data'] if not args.output else 'saved'},indent=2))


if __name__=='__main__':
    main()
