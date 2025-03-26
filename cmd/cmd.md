# Add to /etc/hosts
echo "192.168.122.119 vm1" | sudo tee -a /etc/hosts
echo "192.168.122.189 vm2" | sudo tee -a /etc/hosts
echo "10.66.66.1 vps" | sudo tee -a /etc/hosts

# Connect to ssh
ssh vm@vm1
ssh vm@vm2
ssh vps

# Mount to vm
## On vm
mkdir ter

## In code-ter
mkdir vm/vm1
mkdir vm/vm2
mkdir vm/vps

## Mount
sshfs vm@vm1:ter vm/vm1
sshfs vm@vm2:ter vm/vm2
sshfs vps:ter vm/vps

# Install python env
pip freeze > requirements.txt

cp requirements.txt vm/vm1
cp requirements.txt vm/vm2
cp requirements.txt vm/vps

python3 -m venv .env
source .env/bin/activate
pip3 install -r requirements.txt

# Execute code
## On code-ter
rm vm/vm1/code -r; cp code vm/vm1/code -r;
rm vm/vm2/code -r; cp code vm/vm2/code -r;
rm vm/vps/code -r; cp code vm/vps/code -r;

## On vm
source .env/bin/activate

### Benchmark Config
benchmark_config="--operation all --nb_runs 5 --msg_size 1024 --msg_nb 16"
benchmark_config="--operation add_encrypted --nb_runs 5 --msg_size 4,6,8,10 --msg_nb 16"
benchmark_config="--operation add_encrypted --nb_runs 1 --msg_size 1024 --msg_nb 4"

benchmark_config="--operation add_encrypted --nb_runs 1 --msg_size 4,6,8,10 --msg_nb 16"
benchmark_config="--operation add_encrypted --nb_runs 1 --msg_nb 1,2,3,4,5,6"

benchmark_config="--operation div --nb_runs 5 --msg_size 1024 --msg_nb 16 --use_phe True --folder_prefix xxx"

### Client Server
python code/phe_benchmark.py --client vm1 $benchmark_config
python code/phe_benchmark.py --server $benchmark_config

### Remove rp
rm results_profile/* -rf