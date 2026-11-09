"""One isolated offline phase; preflight never launches a model or emits study decisions."""
import argparse
import errno
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.repeated_triage import load_inputs, select_job, request_rows
from study.final_triage_contract import digest
from study.filtering_policy import canonical, baseline, chat_request
from study.triage_expanded import retain_all, input_format
from study.triage_pilot import classify_completion
from study.filter_input_contract import validate_decision
from engineering.triage_expanded_probe import write, validate_accounting, server_resources, post
from engineering.triage_measurement import RequestMemory, cgroup_memory, process_memory


def network_observation():
    observation = {'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()),
                   'routes': Path('/proc/net/route').read_text()}
    try:
        with socket.create_connection(('192.0.2.1', 443), timeout=2):
            observation['external_route_blocked'] = False
    except OSError as error:
        observation['external_route_blocked'] = error.errno == errno.ENETUNREACH
    if observation['interfaces'] != ['lo'] or not observation['external_route_blocked']:
        raise ValueError('Offline container boundary not established')
    return observation


def model_phase(data, job, out, result):
    process = None
    model = job['model']
    start = time.monotonic()
    try:
        Path('/tmp/slots').mkdir(exist_ok=True)
        args = ['/runtime/llama-server', '-m', '/model.gguf', '--offline', '--host', '127.0.0.1',
                '--port', '10080', '-c', '4096', '-t', '8', '-tb', '8', '-np', '1',
                '-ngl', '0', '--reasoning', 'off', '--slots', '--slot-save-path', '/tmp/slots/']
        env = dict(os.environ, LD_LIBRARY_PATH='/runtime', HF_HUB_OFFLINE='1',
                   OMP_NUM_THREADS='8', OPENBLAS_NUM_THREADS='1')
        with (out / 'server.log').open('x') as log:
            process = subprocess.Popen(args, env=env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + data['execution']['server_readiness_timeout_seconds']
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Server exited before readiness')
            try:
                with urllib.request.urlopen('http://127.0.0.1:10080/health', timeout=2) as response:
                    if json.load(response).get('status') == 'ok':
                        break
            except (OSError, ValueError):
                time.sleep(1)
        else:
            raise TimeoutError('Server readiness timeout')
        result['load_seconds'] = time.monotonic() - start
        with urllib.request.urlopen('http://127.0.0.1:10080/props', timeout=5) as response:
            write(out / 'server_properties.json', json.load(response))

        def infer(packet, payload, prefix, expected, limit, synthetic=False):
            started = time.monotonic()
            write(out / (prefix + '-request.json'), payload)
            write(out / 'progress.json', {'phase': 'synthetic' if synthetic else 'study',
                  'job_id': job['job_id'], 'request_id': prefix, 'finding_id': packet['finding_id'],
                  'completed_study_generations': result['study_generations']})
            row = {'request_id': prefix, 'job_id': job['job_id'], 'finding_id': packet['finding_id'],
                   'model': model, 'block': job['block'], 'packet_sha256': digest(packet),
                   'request_sha256': digest(payload), 'synthetic': synthetic,
                   'expected_prompt_tokens': expected, 'output_limit': limit}
            try:
                before_reset = time.monotonic()
                reset = post('/slots/0?action=erase', {}, out / (prefix + '-reset.raw'))
                row['reset_seconds'] = time.monotonic() - before_reset
                if reset.get('id_slot') != 0 or type(reset.get('n_erased')) is not int:
                    raise ValueError('Slot erasure was not confirmed')
                row['server_before'] = server_resources(process.pid)
                observer = RequestMemory(process.pid)
                try:
                    with observer:
                        start_request = time.monotonic()
                        response = post('/v1/chat/completions', payload, out / (prefix + '-response.raw'))
                        row['request_seconds'] = time.monotonic() - start_request
                finally:
                    (out / (prefix + '-memory.jsonl')).write_text(''.join(canonical(s) + '\n' for s in observer.samples))
                    if observer.samples:
                        row['memory'] = observer.summary()
                row['server_after'] = server_resources(process.pid)
                result['synthetic_generations' if synthetic else 'study_generations'] += 1
                row['accounting'] = validate_accounting(response, expected, limit)
                if not synthetic:
                    started_validation = time.monotonic()
                    row['decision'] = classify_completion(response, packet, validate_decision)
                    row['validation_seconds'] = time.monotonic() - started_validation
                row['success'] = True
            except Exception as error:
                row.update(success=False, error=type(error).__name__ + ': ' + str(error))
                if not synthetic:
                    row['decision'] = {'finding_id': packet['finding_id'], 'status': 'execution_failure',
                                       'action': 'retain', 'effective_action': 'retain'}
                raise
            finally:
                row['decision_interval_seconds'] = time.monotonic() - started
                write(out / (prefix + '-measurement.json'), row)
                write(out / 'probe.json', result)
            return row

        warmup_start = time.monotonic()
        packet = data['warmup']['synthetic_packet']
        payload = {**chat_request(packet, max_tokens=1), 'cache_prompt': False, 'id_slot': 0}
        for index in range(2):
            infer(packet, payload, 'synthetic-' + str(index + 1), data['warmup']['synthetic_prompt_tokens'][model], 1, True)
        result['warmup_seconds'] = time.monotonic() - warmup_start
        with (out / 'decisions.jsonl').open('x') as stream:
            for prefix, specification, packet, payload in request_rows(data, job):
                row = infer(packet, payload, prefix, specification['expected_prompt_tokens'], 384)
                row.update(condition=specification['condition'], input_format=input_format(packet))
                stream.write(canonical(row) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
                result['study_decisions'] += 1
        if (result['study_generations'], result['study_decisions'], result['synthetic_generations']) != (176, 176, 2):
            raise ValueError('Incomplete model phase')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        result['server_resources'] = {'max_rss_kib': usage.ru_maxrss,
            'user_cpu_seconds': usage.ru_utime, 'system_cpu_seconds': usage.ru_stime}


def baseline_phase(data, job, out, result):
    policy = retain_all if job['condition'] == 'B0' else baseline
    packets = [data['packet_index']['alert_only', fid] for fid in job['case_order']]
    with (out / 'decisions.jsonl').open('x') as stream:
        for packet in packets:
            start = time.monotonic()
            cpu = time.process_time_ns()
            decision = policy(packet)
            policy_ns = time.process_time_ns() - cpu
            row = {'job_id': job['job_id'], 'block': job['block'], 'condition': job['condition'],
                   'finding_id': packet['finding_id'], 'decision': decision, 'packet_sha256': digest(packet),
                   'policy_cpu_ns_single_pass': policy_ns, 'policy_interval_seconds': time.monotonic() - start,
                   'process_memory': process_memory(os.getpid()), 'cgroup_memory': cgroup_memory()}
            stream.write(canonical(row) + '\n')
            stream.flush()
            result['study_decisions'] += 1
        os.fsync(stream.fileno())
    batches = []
    for index in range(data['execution']['baseline_timing_batches']):
        start = time.perf_counter_ns()
        cpu = time.process_time_ns()
        retained = 0
        for _ in range(data['execution']['baseline_passes_per_batch']):
            for packet in packets:
                retained += policy(packet)['effective_action'] == 'retain'
        wall, used = time.perf_counter_ns() - start, time.process_time_ns() - cpu
        calls = len(packets) * data['execution']['baseline_passes_per_batch']
        batches.append({'batch': index, 'complete_passes': data['execution']['baseline_passes_per_batch'],
                        'cases_per_pass': len(packets), 'policy_calls': calls, 'retained_decisions': retained,
                        'wall_ns': wall, 'cpu_ns': used, 'wall_ns_per_call': wall / calls, 'cpu_ns_per_call': used / calls})
    write(out / 'timing_batches.json', batches)
    result['timing_batches'] = len(batches)
    result['timing_policy_calls'] = sum(b['policy_calls'] for b in batches)
    if result['study_decisions'] != 88:
        raise ValueError('Incomplete deterministic phase')


def run_phase(data, job, out, mode, result):
    if mode not in ('preflight', 'execute'):
        raise ValueError('Unknown probe mode')
    if mode == 'preflight':
        if job['kind'] == 'model' and (not Path('/model.gguf').is_file() or not Path('/runtime/llama-server').is_file()):
            raise ValueError('Model/runtime mount is absent')
        result['validated_requests'] = len(list(request_rows(data, job))) if job['kind'] == 'model' else 0
        result['models_invoked'] = False
    elif job['kind'] == 'model':
        result['models_invoked'] = True
        model_phase(data, job, out, result)
    else:
        result['models_invoked'] = False
        baseline_phase(data, job, out, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('preflight', 'execute'), required=True)
    parser.add_argument('--job-id', required=True)
    args = parser.parse_args()
    out = Path('/output')
    start = time.monotonic()
    result = {'success': False, 'mode': args.mode, 'job_id': args.job_id,
              'study_generations': 0, 'synthetic_generations': 0, 'study_decisions': 0,
              'timing_scope': 'Warm resident model with erased prompt cache; startup separate; no OS cache flush.'}
    try:
        result.update(network_observation())
        data = load_inputs('/inputs')
        job = select_job(data, args.job_id)
        result.update(input_loading_seconds=time.monotonic() - start, expected_jobs=len(data['schedule']),
                      expected_cases=len(data['ids']), cgroup_before=cgroup_memory())
        run_phase(data, job, out, args.mode, result)
        result['success'] = True
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['elapsed_seconds'] = time.monotonic() - start
        result['cgroup_after'] = cgroup_memory()
        write(out / 'probe.json', result)
    if not result['success']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
