#!/bin/bash
# This script is used by launch config in Visual Studio Code when debugging bittwist.
# It will run gdb as root since bittwist requires root access.
pkexec /usr/bin/gdb "$@"
