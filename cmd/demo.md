# Setup
## Host
echo "192.168.122.119 vm1" | sudo tee -a /etc/hosts
echo "192.168.122.189 vm2" | sudo tee -a /etc/hosts

mkdir vm/vm1
mkdir vm/vm2

sshfs vm@vm1:ter vm/vm1
sshfs vm@vm2:ter vm/vm2

## On VM
ssh vm@vm1
ssh vm@vm2

mkdir ter

## Host
rm vm/vm1/code -r; cp code vm/vm1/code -r;
rm vm/vm2/code -r; cp code vm/vm2/code -r;

## On VM
cd ter; source .env/bin/activate

python code/he_benchmark.py --client vm1 $benchmark_config
python code/he_benchmark.py --server $benchmark_config

benchmark_config=" --port 12345 --nb_runs 5 --nb_data 512 --key_length 4096 --nb_operations 32 --folder_prefix demo --operation add_encrypted --scheme bfv,ckks,tfhe"


### if no env
#### host
cp requirements.txt vm/vm1
cp requirements.txt vm/vm2

#### vm
python3 -m venv .env
source .env/bin/activate
pip3 install -r requirements.txt