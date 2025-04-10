#!/bin/bash

setcap 'cap_net_bind_service=+ep' ./src/potato
