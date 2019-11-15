#!/usr/bin/env bash

analyze_headless_path=~/build/ghidra_9.1-BETA_DEV_20190923/ghidra_9.1-BETA_DEV/support/analyzeHeadless
project_path=~/doc/projects/romhack/ghidra-smb2
folder_path=smb2/gc-sdk

"$analyze_headless_path" "$project_path" "$folder_path" -process '*.o' -recursive -postScript ExportXmlAndBinary.java -max-cpu "$(nproc)"
