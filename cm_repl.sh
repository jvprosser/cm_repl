#!/bin/bash

CM_REPL_PATH=/home/jprosser/cm_repl

if [ ! -x /usr/lib64/cmf/agent/build/env/bin/python ] ; then
    echo "Missing CM Python environment. Is the CM agent installed on this system?"
    exit 1
fi


/usr/lib64/cmf/agent/build/env/bin/python ${CM_REPL_PATH}/cm_repl.pyc "$@"

exit $?

