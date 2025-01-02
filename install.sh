#!/usr/bin/env bash

cd target/release
cp sklep /usr/local/bin/
setcap cap_sys_rawio+ep /usr/local/bin/sklep
cp libsklep.so /lib64/security/
