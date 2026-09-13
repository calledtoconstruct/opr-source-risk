#!/bin/bash
setcap cap_net_admin+ep /usr/bin/app
chmod u+s /usr/bin/app
