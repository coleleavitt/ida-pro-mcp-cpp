#!/bin/bash
cd build || return
cp ida_mcp_plugin64.so ~/.idapro/plugins
cp ida_mcp_plugin64.so ~/Downloads/Software/IDAPro/ida-pro-9.1/plugins/
