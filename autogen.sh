#!/bin/sh

test -n "$projdir" || projdir=`dirname "$0"`
test -n "$projdir" || projdir=.

autoreconf --force --install --verbose "$projdir"
