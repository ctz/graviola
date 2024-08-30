#!/bin/sh
set -e
for d in driver.*.py ; do
  python $d
done
