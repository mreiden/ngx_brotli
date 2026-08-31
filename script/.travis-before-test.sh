#!/bin/bash
set -ex

# Setup shortcuts.
ROOT=`pwd`
FILES=$ROOT/script/test

# Setup directory structure.
cd $ROOT/script
if [ ! -d test ]; then
  mkdir test
fi
cd test
if [ ! -d logs ]; then
  mkdir logs
fi

# Download sample texts.
# -fL + https (CodeRabbit on the graft): without -f a 404 stores an HTML
# error page as the fixture and the suite "passes" against it; gutenberg
# redirects plain http, so without -L the body is the redirect notice.
curl -fsSL --compressed -o $FILES/war-and-peace.txt https://www.gutenberg.org/files/2600/2600-0.txt
echo "Kot lomom kolol slona!" > $FILES/small.txt
echo "<html>Kot lomom kolol slona!</html>" > $FILES/small.html

# Restore status-quo.
cd $ROOT
