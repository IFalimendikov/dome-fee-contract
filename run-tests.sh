#!/bin/bash
export PATH="$HOME/.foundry/bin:$PATH"

forge build
forge test -vvv
