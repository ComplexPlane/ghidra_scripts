#!/usr/bin/env bash

analyze_headless_path="$GHIDRA_INSTALL_DIR"/support/analyzeHeadless
project_path=~/doc/projects/romhack/mkb2-decompilation
# folder_path=mkb2-decompilation/musyx-v15-2001_6_22.a
# folder_path=mkb2-decompilation/musyx-v15-2002_4_12.a
folder_path=mkb2-decompilation/musyx-v20-2004.a

"$analyze_headless_path" "$project_path" "$folder_path" -process '*.o' -recursive -postScript ExportXmlAndBinary.java -max-cpu "$(nproc)"
