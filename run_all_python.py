#!/usr/bin/env python3
"""
run_all_python.py
Запускает bruteforce_cracker.py по всем хэшам/уровням и собирает результаты в CSV.
Требования: bruteforce_cracker.py должен поддерживать вывод в формате:
    FOUND: <password>  attempts~<n> elapsed=<s>s H/s~<hps>
или
    NOT FOUND ... attempts~<n> elapsed=<s>s H/s~<hps>

Запуск:
    python run_all_python.py --procs 12 --chunk 20000 --time-limit 60
(укажите --time-limit если хотите ограничить время на каждый тест)
"""
import csv
import subprocess
import shlex
import argparse
import sys
import os
import re

# Тестовые хэши (взятые из задания)
TESTS = {
    'sha1': [
        ('легкий','7c4a8d09ca3762af61e59520943dc26494f8941b'),
        ('средний','d0be2dc421be4fcd0172e5afceea3970e2f3d940'),
        ('сложный','666846867fc5e0a46a7afc53eb8060967862f333'),
        ('очень сложный','6e157c5da4410b7e9de85f5c93026b9176e69064'),
    ],
    'md5': [
        ('легкий','e10adc3949ba59abbe56e057f20f883e'),
        ('средний','1f3870be274f6c49b3e31a0c6728957f'),
        ('сложный','77892341aa9dc66e97f5c248782b5d92'),
        ('очень сложный','686e697538050e4664636337cc3b834f'),
    ],
    'bcrypt': [
        ('легкий','$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi'),
        ('средний','$2a$10$26GB/T2/6aTsMkTjCgqm/.JP8SUjr32Bhfn9m9smtDiIwM4QIt2ze'),
        ('сложный','$2a$10$Q9M0vLLrE4/nu/9JEMXFTewB3Yr9uMdIEZ1Sgdk1NQTjHwLN0asfi'),
        ('очень сложный','$2a$10$yZBadi8Szw0nItV2g96P6eqctI2kbG/.mb0uD/ID9tlof0zpJLLL2'),
    ],
    'argon2': [
        ('легкий','$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c'),
        ('средний','$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$HYQwRUw9VcfkvqkUQ5ppyYPom6f/ro3ZCXYznhrYZw4'),
        ('сложный','$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$9asGA7Xv3vQBz7Yyh4/Ntw0GQgOg8R6OWolOfRETrEg'),
        ('очень сложный','$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$+smq45/czydGj0lYNdZVXF++FOXJwrkXt6VUIcEauvo'),
    ]
}

# PRESets keyspace: match previous message
PRESETS = {
    'легкий':   {'charset':'0123456789','min':1,'max':6},
    'средний':  {'charset':'0123456789abcdefghijklmnopqrstuvwxyz','min':1,'max':6},
    'сложный':  {'charset':'0123456789abcdefghijklmnopqrstuvwxyz','min':1,'max':7},
    'очень сложный': {'charset':'0123456789abcdefghijklmnopqrstuvwxyz','min':1,'max':8},
}

def parse_output(output):
    # Попытка найти "FOUND" или "NOT FOUND" + attempts/elapsed
    s = output.replace('\r','\n')
    found = False
    pwd = ''
    attempts = 0
    elapsed = 0.0
    hps = 0.0
    m = re.search(r'FOUND:\s*(\S+)\s+attempts~(\d+)\s+elapsed=([0-9.]+)s\s+H/s~([0-9.]+)', s)
    if m:
        found = True
        pwd = m.group(1)
        attempts = int(m.group(2))
        elapsed = float(m.group(3))
        hps = float(m.group(4))
        return found,pwd,attempts,elapsed,hps
    # либо try to match NOT FOUND pattern
    m2 = re.search(r'NOT FOUND.*attempts~(\d+).*elapsed=([0-9.]+)s\s+H/s~([0-9.]+)', s)
    if m2:
        attempts = int(m2.group(1))
        elapsed = float(m2.group(2))
        hps = float(m2.group(3))
        return False,'',attempts,elapsed,hps
    # Fallback: попытаться найти attempts и elapsed
    m3 = re.search(r'attempts~(\d+).*elapsed=([0-9.]+)s', s)
    if m3:
        attempts = int(m3.group(1))
        elapsed = float(m3.group(2))
        return False,'',attempts,elapsed, (attempts/elapsed if elapsed>0 else 0.0)
    return False,'',0,0.0,0.0

def run_one(alg, level_name, target_hash, args):
    preset = PRESETS[level_name]
    charset = preset['charset']
    minl = preset['min']
    maxl = preset['max']
    cmd = f'python bruteforce_cracker.py --alg {alg} --hash "{target_hash}" --charset {charset} --min {minl} --max {maxl} --procs {args.procs} --chunk {args.chunk}'
    if args.time_limit:
        cmd += f' --time-limit {args.time_limit}'
    print("RUN:", cmd)
    # запускаем и захватываем stdout
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out_lines = []
    try:
        stdout, _ = proc.communicate(timeout=args.timeout_per_test)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout = proc.stdout.read() if proc.stdout else ''
    print(stdout)
    found,pwd,attempts,elapsed,hps = parse_output(stdout)
    return {
        'algorithm': alg,
        'level': level_name,
        'target_hash': target_hash,
        'charset': charset,
        'min': minl,
        'max': maxl,
        'found': found,
        'password': pwd,
        'attempts': attempts,
        'elapsed': elapsed,
        'hps': hps
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--procs', type=int, default=12)
    parser.add_argument('--chunk', type=int, default=20000)
    parser.add_argument('--time-limit', type=float, default=None, help='per-test time limit (pass to bruteforce_cracker)')
    parser.add_argument('--timeout-per-test', type=float, default=600.0, help='timeout for subprocess call')
    parser.add_argument('--out', default='python_results.csv')
    args = parser.parse_args()

    rows = []
    for alg, items in TESTS.items():
        for level_name, target_hash in items:
            res = run_one(alg, level_name, target_hash, args)
            rows.append(res)
            # optional: flush to CSV incrementally
            with open(args.out, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['algorithm','level','target_hash','charset','min','max','found','password','attempts','elapsed','hps'])
                for r in rows:
                    writer.writerow([r[k] for k in ['algorithm','level','target_hash','charset','min','max','found','password','attempts','elapsed','hps']])
    print("Saved:", args.out)

if __name__ == '__main__':
    main()
