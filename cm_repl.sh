#!/bin/bash

if [ ! -x /usr/lib64/cmf/agent/build/env/bin/python ] ; then
    echo "Missing CM Python environment. Is the CM agent installed on this system?"
    exit 1
fi
