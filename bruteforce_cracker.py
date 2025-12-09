#!/usr/bin/env python3
"""
Optimized bruteforce_cracker.py без прямого использования модуля bcrypt.

Поддерживает:
  - md5
  - sha1
  - bcrypt (через passlib, чисто-питоновский backend)
  - argon2 (через argon2-cffi)

Примеры запуска:
  python bruteforce_cracker.py --alg md5 --hash e10adc3949ba59abbe56e057f20f883e --charset 0123456789 --min 1 --max 6 --procs 8 --chunk 10000
  python bruteforce_cracker.py --alg sha1 --hash 7c4a8d09ca3762af61e59520943dc26494f8941b --charset 0123456789 --min 1 --max 6 --procs 8 --chunk 10000
"""

import argparse
import hashlib
import itertools
import time
from multiprocessing import cpu_count, Pool

import os

# Включаем чисто-питоновский backend bcrypt в passlib (иначе он по умолчанию отключен)
# https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html
os.environ.setdefault("PASSLIB_BUILTIN_BCRYPT", "enabled")

# ----- backends -----
HAS_PW_BCRYPT = True
try:
    from passlib.hash import bcrypt as pw_bcrypt
except Exception:
    HAS_PW_BCRYPT = False

HAS_ARGON2 = True
try:
    from argon2 import PasswordHasher, exceptions as argon2_ex
except Exception:
    HAS_ARGON2 = False
    PasswordHasher = None
    argon2_ex = None


# ----- worker: проверяет список кандидатов -----
def worker_check(args):
    candidates, target_hash, alg = args
    target_hash = target_hash.strip().lower()

    if alg == 'md5':
        for s in candidates:
            if hashlib.md5(s.encode()).hexdigest() == target_hash:
                return s

    elif alg == 'sha1':
        for s in candidates:
            if hashlib.sha1(s.encode()).hexdigest() == target_hash:
                return s

    elif alg == 'bcrypt':
        if not HAS_PW_BCRYPT:
            raise RuntimeError("bcrypt backend (passlib) недоступен — проверьте установку 'passlib'")
        for s in candidates:
            try:
                if pw_bcrypt.verify(s, target_hash):
                    return s
            except Exception:
                # неверный формат, ошибка backend'a — просто пропускаем
                continue

    elif alg == 'argon2':
        if not HAS_ARGON2:
            raise RuntimeError("argon2 backend (argon2-cffi) недоступен — установите 'argon2-cffi'")
        ph = PasswordHasher()
        for s in candidates:
            try:
                if ph.verify(target_hash, s):
                    return s
            except argon2_ex.VerifyMismatchError:
                continue
            except Exception:
                continue

    return None


# ----- генерация кандидатов -----
from itertools import islice


def iter_chunks(it, chunk_size):
    """Разбивает произвольный итератор на чанки по chunk_size элементов."""
    it = iter(it)
    while True:
        chunk = list(islice(it, chunk_size))
        if not chunk:
            break
        yield chunk


def product_strings(charset, length):
    """Все строки заданной длины из указанного алфавита."""
    for tpl in itertools.product(charset, repeat=length):
        yield ''.join(tpl)


# ----- основной bruteforce -----
def brute_force(target_hash, alg, charset, min_len, max_len, procs, chunk_size, time_limit=None):
    """
    Полный перебор паролей в заданном keyspace.
    Возвращает (found_password or None, attempts, elapsed_seconds).
    """
    tstart = time.time()
    attempts = 0

    with Pool(processes=procs) as pool:
        for L in range(min_len, max_len + 1):
            gen = product_strings(charset, L)
            for chunk in iter_chunks(gen, chunk_size):
                # проверка лимита времени
                if time_limit and (time.time() - tstart) > time_limit:
                    elapsed = time.time() - tstart
                    return None, attempts, elapsed

                attempts += len(chunk)

                # один вызов worker_check на один чанк
                res = pool.apply_async(worker_check, ((chunk, target_hash, alg),))
                found_res = res.get()  # ждём завершения обработки чанка
                if found_res:
                    elapsed = time.time() - tstart
                    return found_res, attempts, elapsed

    elapsed = time.time() - tstart
    return None, attempts, elapsed


# ----- CLI -----
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--alg', choices=['md5', 'sha1', 'bcrypt', 'argon2'], required=True)
    p.add_argument('--hash', required=True)
    p.add_argument('--charset', default='0123456789abcdefghijklmnopqrstuvwxyz')
    p.add_argument('--min', type=int, default=1)
    p.add_argument('--max', type=int, default=6)
    p.add_argument('--procs', type=int, default=max(1, cpu_count() - 1))
    p.add_argument('--chunk', type=int, default=5000, help='кандидатов в одном чанке')
    p.add_argument('--time-limit', type=float, default=None, help='лимит времени на прогон, секунды (None = без лимита)')
    return p.parse_args()


def main():
    args = parse_args()
    print("Bruteforce (optimized, passlib bcrypt) starting:")
    print(
        f" alg={args.alg} hash={args.hash[:20]}... charset_len={len(args.charset)} "
        f"min={args.min} max={args.max} procs={args.procs} chunk={args.chunk}"
    )

    found, attempts, elapsed = brute_force(
        args.hash,
        args.alg,
        list(args.charset),
        args.min,
        args.max,
        args.procs,
        args.chunk,
        args.time_limit,
    )
    if elapsed <= 0:
        elapsed = 1e-9

    if found:
        print(f"FOUND: {found}  attempts~{attempts} elapsed={elapsed:.3f}s H/s~{attempts / elapsed:.1f}")
    else:
        print(f"NOT FOUND in tested keyspace. attempts~{attempts} elapsed={elapsed:.3f}s H/s~{attempts / elapsed:.1f}")


if __name__ == '__main__':
    main()
