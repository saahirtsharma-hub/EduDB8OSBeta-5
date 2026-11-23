#!/bin/bash
cd /home/claude/debxfce/kernel/src
make -j$(nproc) bzImage modules
echo "BUILD_EXIT=$?"
