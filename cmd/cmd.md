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
cd ter; source .env/bin/activate

### Benchmark Config
benchmark_config="--operation add_encrypted --port 12345 --nb_runs 2 --nb_patients 2 --nb_vitals 8 --key_length 4096 --nb_operations 32 --folder_prefix test --scheme paillier"
benchmark_config="--operation add_encrypted --port 12345 --nb_runs 2 --nb_patients 1 --nb_vitals 1024 --key_length 4096 --nb_operations 256 --folder_prefix test --scheme bfv"
benchmark_config="--operation add_encrypted --port 12345 --nb_runs 5 --nb_patients 1 --nb_vitals 512 --key_length 4096,8192 --nb_operations 32 --folder_prefix scheme --scheme ckks"

benchmark_config="--operation add_encrypted --port 12345 --nb_runs 10 --nb_patients 1 --nb_vitals 1024 --key_length 4096 --nb_operations 256 --folder_prefix comp2 --scheme bfv,ckks"
benchmark_config="--operation add_encrypted --port 12345 --nb_runs 1 --nb_patients 1 --nb_vitals 1024 --key_length 4096 --nb_operations 256 --folder_prefix 3scheme --scheme tfhe"


### Client Server
python code/he_benchmark.py --client vm1 $benchmark_config
python code/he_benchmark.py --server $benchmark_config
python code/benchmark.py

### Remove rp
rm results_profile/* -rf