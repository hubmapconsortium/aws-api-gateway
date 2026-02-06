#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Specify the name of the zip file as deployed in AWS Lambda Layers, and
# as commited to the repository, so it the base of the filename can be
# used in prefixing zip archive entries.
ARCHIVE_FILENAME='python.zip'
ARCHIVE_BASENAME="${ARCHIVE_FILENAME%%.*}"

# Point to the directory where pip places requirements.txt entries and
# dependencies relative to the location of this script.
REQS_INSTALL_DIR=../.venv/lib/python3.13/site-packages

# Save the location of this script, which is where the archive file will be placed.
SCRIPT_DIR="$(pwd)"

# Grab a consistent time stamp to be used on files placed in the archive file
TOUCH_TIME=$(date --utc +%Y%m%d%H%M.%S)
echo "Executing ${0} to create"
echo "${SCRIPT_DIR}/${ARCHIVE_BASENAME}${TOUCH_TIME}.zip using the content"
echo "of ${REQS_INSTALL_DIR}"

# Create a directory and rsync everything there, just so we can get a
# "${ARCHIVE_BASENAME}" prefix on each archive entry with a primitive version of
# zip (the one Linux likes from 2008.)
if [[ -d "/tmp/$(whoami)/${ARCHIVE_BASENAME}${TOUCH_TIME}/${ARCHIVE_BASENAME}" ]]; then
  echo "/tmp/$(whoami)/${ARCHIVE_BASENAME}${TOUCH_TIME}/${ARCHIVE_BASENAME} already exists, giving up."
  exit 2
fi
mkdir -p "/tmp/$(whoami)/${ARCHIVE_BASENAME}${TOUCH_TIME}/${ARCHIVE_BASENAME}"

cd "${REQS_INSTALL_DIR}"
rsync -a . "/tmp/$(whoami)/${ARCHIVE_BASENAME}${TOUCH_TIME}/${ARCHIVE_BASENAME}"
cd "/tmp/$(whoami)/${ARCHIVE_BASENAME}${TOUCH_TIME}"

# touch the files so everything is timestamped the same in the zip file,
# just for reference.
find . -exec touch -h -t ${TOUCH_TIME} {} +

# Create the zip file with maximum compression, excluding
# filesystem metadata like UID/GID, atime, etc.
# and leaving out unwanted files during recursion.
TZ=UTC zip -r9X ${SCRIPT_DIR}/${ARCHIVE_BASENAME}${TOUCH_TIME}.zip ${ARCHIVE_BASENAME} \
  -x "*.pyc" "__pycache__/*"

echo "Done creating ${SCRIPT_DIR}/${ARCHIVE_BASENAME}${TOUCH_TIME}.zip"
echo "After evaluation, move ${ARCHIVE_BASENAME}${TOUCH_TIME}.zip to ${ARCHIVE_BASENAME}.zip for"
echo "commiting to Git and deployment in AWS Lambda."
