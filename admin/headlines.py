#!/usr/bin/python

from os import path
import json
import tomllib
from io import StringIO

archs = "aarch64 x86_64".split()
impls = "aws-lc-rs dalek ring graviola rustcrypto golang".split()
which = [
    {
        "key": "rsa2048-pkcs1-sha256-verify",
        "name": "RSA2048 signature verification",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> sigs/sec".format(v),
    },
    {
        "key": "rsa2048-pkcs1-sha256-sign",
        "name": "RSA2048 signing",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> sigs/sec".format(v),
    },
    {
        "key": "p256-ecdsa-sign",
        "name": "ECDSA-P256 signing",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> sigs/sec".format(v),
    },
    {
        "key": "p384-ecdsa-sign",
        "name": "ECDSA-P384 signing",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> sigs/sec".format(v),
    },
    {
        "key": "p256-ecdsa-verify",
        "name": "ECDSA-P256 signature verification",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> sigs/sec".format(v),
    },
    {
        "key": "p384-ecdsa-verify",
        "name": "ECDSA-P384 signature verification",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> sigs/sec".format(v),
    },
    {
        "key": "x25519-ecdh",
        "name": "X25519 key agreement",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> kx/sec".format(v),
    },
    {
        "key": "p256-ecdh",
        "impl-alias": dict(rustcrypto="p256-rustcrypto"),
        "name": "P256 key agreement",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> kx/sec".format(v),
    },
    {
        "key": "p384-ecdh",
        "impl-alias": dict(rustcrypto="p384-rustcrypto"),
        "name": "P384 key agreement",
        "format": lambda v: "<data value='{0}'>{0:,.5g}</data> kx/sec".format(v),
    },
    {
        "key": "aes256-gcm",
        "size": "8KB",
        "name": "AES256-GCM encryption (8KB wide)",
        "format": lambda v: "<data value='{0}'>{1:,.03g}</data> GiB/sec".format(
            v, v * 8192 / (1024 * 1024 * 1024)
        ),
    },
]

notes = {
    "x86_64": {
        "aws-lc-rs": {
            "aes256-gcm": "Uses AVX512",
            "rsa2048-pkcs1-sha256-sign": "Uses AVX512",
        },
        "ring": {
            "aes256-gcm": "Uses AVX512",
        },
        "graviola": {
            "aes256-gcm": "Uses AVX512",
        },
    }
}


def from_cargo_lock(*packages):
    def _from_cargo_lock(arch):
        out = []
        for package in sorted(packages):
            lock = tomllib.load(open(path.join("reports", arch, "Cargo.lock"), "rb"))
            candidate = [p for p in lock.get("package", []) if p["name"] == package]
            if len(candidate) == 1:
                p = candidate[0]
                out.append("{} <tt>{}</tt>".format(p["name"], p["version"]))
            else:
                print(f"WARNING: no version information for {package} on {arch}")
        return ", ".join(out)

    return _from_cargo_lock


def from_golang_log(arch):
    lines = open(path.join("reports", arch, "report", "golang.txt")).readlines()
    return "<tt>{}</tt>".format(lines[1])


def from_graviola_version(arch):
    version = open(path.join("reports", arch, "graviola-version.txt")).read().strip()
    return "<tt>{}</tt>".format(version)


impl_versions = {
    "aws-lc-rs": from_cargo_lock("aws-lc-rs", "aws-lc-sys"),
    "graviola": from_graviola_version,
    "dalek": from_cargo_lock("x25519-dalek", "curve25519-dalek"),
    "ring": from_cargo_lock("ring"),
    "golang": from_golang_log,
    "rustcrypto": from_cargo_lock("aes-gcm", "sha2", "p256", "p384", "rsa"),
}

results = []

standings = ["🥇", "🥈", "🥉", " ", " "]

groups = [
    ("Signing", ["rsa2048-pkcs1-sha256-sign", "p256-ecdsa-sign", "p384-ecdsa-sign"]),
    (
        "Signature verification",
        ["rsa2048-pkcs1-sha256-verify", "p256-ecdsa-verify", "p384-ecdsa-verify"],
    ),
    ("Key exchange", ["x25519-ecdh", "p256-ecdh", "p384-ecdh"]),
    ("Bulk encryption", ["aes256-gcm"]),
]

for arch in sorted(archs):
    for wdesc in which:
        wkey = wdesc["key"]
        wsize = wdesc.get("size", None)

        for impl in sorted(impls):
            wimpl = wdesc.get("impl-alias", {}).get(impl, impl)
            filename = path.join(
                "reports",
                arch,
                wkey,
                wimpl,
                wsize + "/new" if wsize else "new",
                "estimates.json",
            )
            if not path.exists(filename):
                continue
            data = json.load(open(filename))
            value = data["median"]["point_estimate"]

            results.append((wdesc, arch, impl, value))

tree = {}
for desc, arch, impl, value in results:
    time = value * 1e-9
    rate = 1 / time
    value = desc["format"](rate)
    a = tree.setdefault(arch, {})
    a.setdefault(desc["key"], dict(desc))
    a[desc["key"]].setdefault("measures", {})[impl] = (value, rate)

fragment = StringIO()
for arch, descs in sorted(tree.items()):
    print("<h2>{}</h2>".format(arch), file=fragment)
    for group, keys in groups:
        print(
            "<h3>{}</h3><table width='100%' cellspacing=25 cellpadding=10>".format(
                group
            ),
            file=fragment,
        )
        for key in keys:
            kimpls = descs[key]["measures"]
            print("<tr><td>{}</td>".format(descs[key]["name"]), file=fragment)

            for standing, impl in zip(
                standings,
                sorted(kimpls.keys(), key=lambda b: kimpls[b][1], reverse=True),
            ):
                note = notes.get(arch, {}).get(impl, {}).get(key, None)
                note = (
                    "<span class='info' title='{}'>ⓘ</span>".format(note)
                    if note
                    else ""
                )
                print(
                    "<td class='{}'>{}<h3>{} {}</h3>{}</td>".format(
                        impl, note, standing, impl, kimpls[impl][0]
                    ),
                    file=fragment,
                )
            print("</tr>", file=fragment)

        print("</table>", file=fragment)

    print('<h3 name="versions">Versions tested</h3>', file=fragment)
    for i in sorted(impls):
        print(
            "<li>{} version: {}</li>".format(i, impl_versions[i](arch)), file=fragment
        )

html = open("index.html").readlines()
out = open("index.html.new", "w")

skipping = False
for line in html:
    if not skipping:
        out.write(line)

    if line == "<!-- begin headlines -->\n":
        skipping = True
        out.write(fragment.getvalue())
    if skipping and line == "<!-- end headlines -->\n":
        skipping = False
        out.write(line)
