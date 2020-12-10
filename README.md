# pamela-feeder-2.0
A new feeder for urlab

## Purpose
Feed a REDIS database with the mac addresses on the selected subnet.

## Installation
You'll need to update the `.env` file to match your setup.

```
virtualenv -p python3 ve
source ve/bin/activate
pip install -r requirements.txt
sudo su
source .env
python3 feeder.py
```

## Setup on the machine
We'll use a cron job to run the script every 30 seconds.