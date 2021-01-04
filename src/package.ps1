#!/usr/local/bin/pwsh
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Builds a lambda package from a single Python 3 module with pip dependencies.
# This is a modified version of the AWS packaging instructions:
# https://docs.aws.amazon.com/lambda/latest/dg/lambda-python-how-to-create-deployment-package.html#python-package-dependencies

remove-item -path ..\lambda-zip -recurse -force *>$NULL
new-item -path ..\ -Name lambda-zip -ItemType "directory" >$NULL

cd servicenow-acct-setup-handler
compress-archive -Path .\* -DestinationPath ..\..\lambda-zip\servicenow-acct-setup-handler.zip

cd ..\servicenow-stack-set-handler
compress-archive -Path .\* -DestinationPath ..\..\lambda-zip\servicenow-stack-set-handler.zip
cd ..
