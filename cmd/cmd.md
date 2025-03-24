# Add to /etc/hosts
echo "192.168.122.119 vm1" | sudo tee -a /etc/hosts
echo "192.168.122.189 vm2" | sudo tee -a /etc/hosts

# Connect to ssh
ssh vm@vm1
ssh vm@vm2

# Mount to vm
## On vm
mkdir ter

## In code-ter
mkdir vm/vm1
mkdir vm/vm2

## Mount
sshfs vm@vm1:ter vm/vm1
sshfs vm@vm2:ter vm/vm2

# Create folder
mkdir vm/vm1/results_profile
mkdir vm/vm2/results_profile

# Install python env
cp requirements.txt vm/vm1
cp requirements.txt vm/vm2

python3 -m venv .env
source .env/bin/activate
pip3 install -r requirements.txt

# Execute code
## On code-ter
rm vm/vm1/code -r; rm vm/vm2/code -r; cp code vm/vm1/code -r; cp code vm/vm2/code -r

## On vm
source .env/bin/activate
python3 code/networkPHE.py --server
python3 code/networkPHE.py --client vm1 --operation add

benchmark_config="--operation all --nb_runs 5 --msg_size 1024 --msg_nb 16"
benchmark_config="--operation add_encrypted --nb_runs 5 --msg_size 4,6,8,10 --msg_nb 16"

benchmark_config="--operation add_encrypted --nb_runs 1 --msg_size 4,6,8,10 --msg_nb 4"

python code/phe_benchmark.py --client vm1 $benchmark_config
python code/phe_benchmark.py --server $benchmark_config

rm results_profile/* -rf