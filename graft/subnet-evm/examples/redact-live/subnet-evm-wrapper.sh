#!/bin/sh
# Wrapper for the Subnet-EVM plugin of the authority node.
#
# The usual way to give the trapdoor is the redact-trapdoor-file key of the
# chain config. This is for when it has to come from the environment instead:
# avalanchego only forwards GRPC_* and GODEBUG* variables to the VM process, so
# setting the variable on avalanchego itself does nothing. Copy this file into
# the plugin dir under the VM id
# (srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy), make it executable, and
# fill in the two placeholders.
#
# Nodes that are not the authority don't need the trapdoor: they can use the
# plain subnet-evm binary, or this wrapper without the export line.

export SUBNET_EVM_REDACT_TRAPDOOR="<TRAPDOOR_HEX>"
exec "<PATH_TO>/build/subnet-evm" "$@"
