"""Load only scanner inputs and an ephemeral laboratory token for one profile."""
import argparse
import json
import os
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--tool',choices=('nuclei','schemathesis','zap'),required=True)
    p.add_argument('--input',type=Path,required=True);p.add_argument('--base',required=True);a=p.parse_args()
    token=json.loads((a.input/'authorization.json').read_text())['token'];header='Authorization: Bearer '+token
    if a.tool=='schemathesis':
        binary='<LAB_ROOT>/environment/toolset-completion-20260922-01/python/bin/schemathesis'
        argv=[binary,'run',str(a.input/'openapi.json'),'--url',a.base,'--header',header,
            '--workers','1','--phases','examples,fuzzing','--max-examples','5','--seed','117','--max-time','30',
            '--request-timeout','5','--generation-database','none','--checks','not_a_server_error',
            '--report','json,junit,har','--report-dir',str(a.input/'reports')]
    elif a.tool=='nuclei':
        binary='/usr/local/bin/nuclei';argv=[binary,'-l',str(a.input/'urls.txt'),'-t',str(a.input/'template.yaml'),
            '-H',header,'-jsonl','-o',str(a.input/'nuclei.jsonl'),'-tlog',str(a.input/'requests.jsonl'),
            '-elog',str(a.input/'errors.jsonl'),'-duc','-ni','-silent','-no-stdin','-rl','5','-c','1','-dr','-retries','0','-timeout','5']
    else:
        os.environ.update(ZAP_AUTH_HEADER='Authorization',ZAP_AUTH_HEADER_VALUE='Bearer '+token,ZAP_AUTH_HEADER_SITE='audit-proxy')
        binary='/zap/zap-api-scan.py';argv=[binary,'-t','/zap/wrk/openapi.json','-f','openapi','-J','zap.json','-P','10091','-T','3',
            '-z','-silent -notel -config connection.timeoutInSecs=5 -config scanner.maxScanDurationInMins=1 -config scanner.threadPerHost=2']
    os.execv(binary,argv)


if __name__=='__main__':main()
