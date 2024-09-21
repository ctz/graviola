#!/usr/bin/env python3

import subprocess
import os
import json
from os import path

OUTPUT_PATH = "target/criterion"

extra = ["-benchtime", "5s"]

version = subprocess.check_output(["go", "version"], encoding="utf-8").strip()

print(version)


def measure(module, suite):
    print(f"MEASURE: {module} {suite}")
    cmd = ["go", "test", module, "-bench", suite] + extra
    lines = subprocess.check_output(
        cmd,
        encoding="utf-8",
    ).splitlines()

    transcript = "$ {}\n{}\n".format(" ".join(cmd), "\n".join(lines))

    for line in lines:
        if line.startswith(suite):
            parts = line.split()
            assert "ns/op" in parts[3]
            value = float(parts[2])
            secs = value * 1e-9
            print("=> {:g} ops/sec".format(1 / secs))
            return value, transcript


def insert_criterion_result(result, slug):
    p = path.join(OUTPUT_PATH, slug, "new")
    os.makedirs(p, exist_ok=True)

    obj = dict(median=dict(point_estimate=result))
    json.dump(obj, open(path.join(p, "estimates.json"), "w"))


# only measure "headlines" (see headlines.py on gh-pages branch)
rsa_pkcs_sign, rsa_sign_transcript = measure("crypto/rsa", "BenchmarkSignPKCS1v15/2048")
rsa_pkcs_verify, rsa_verify_transcript = measure(
    "crypto/rsa", "BenchmarkVerifyPKCS1v15/2048"
)
aead_aesgcm256, aes_transcript = measure(
    "crypto/cipher", "BenchmarkAESGCM/Open-256-8192"
)
x25519_ecdh, x25519_transcript = measure("crypto/ecdh", "BenchmarkECDH/X25519")

insert_criterion_result(rsa_pkcs_sign, "rsa2048-pkcs1-sha256-sign/golang")
insert_criterion_result(rsa_pkcs_verify, "rsa2048-pkcs1-sha256-verify/golang")
insert_criterion_result(aead_aesgcm256, "aes256-gcm/golang/8KB")
insert_criterion_result(x25519_ecdh, "x25519-ecdh/golang")

os.makedirs(path.join(OUTPUT_PATH, "report"), exist_ok=True)
with open(path.join(OUTPUT_PATH, "report", "golang.txt"), "w") as f:
    print(
        f"""$ go version
{version}

{rsa_sign_transcript}

{rsa_verify_transcript}

{aes_transcript}

{x25519_transcript}
""",
        file=f,
    )
