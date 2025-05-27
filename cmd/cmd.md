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

### Add c2p / c2c
<!-- benchmark_config=" --port 12345 --nb_runs 10 --nb_data 512 --key_length 4096 --nb_operations 4 --folder_prefix c2p_c2c --operation mul_scalar,mul_encrypted --scheme bfv,ckks"
// faire pour 10 -->

### Add Encrypt
benchmark_config=" --port 12345 --nb_runs 2 --nb_data 1024 --key_length 4096 --nb_operations 128 --folder_prefix test --operation add_encrypted --scheme bfv"

benchmark_config=" --port 12345 --nb_runs 10 --nb_data 16 --key_length 4096 --nb_operations  --folder_prefix add_encrypt --operation paillier_bfv --scheme paillier,bfv,ckks,tfhe"

--

benchmark_config=" --port 12345 --nb_runs 10 --nb_data 16 --key_length 4096 --nb_operations 16 --folder_prefix paillier_bfv --operation add_encrypted --scheme paillier,bfv

benchmark_config=" --port 12345 --nb_runs 10 --nb_data 512 --key_length 4096 --nb_operations 32 --folder_prefix add_encrypt2 --operation add_encrypted --scheme paillier,bfv,ckks,tfhe"

### Mul Encrypt
benchmark_config=" --port 12345 --nb_runs 10 --nb_data 64 --key_length 4096 --nb_operations 16 --folder_prefix mul_encrypt --operation mul_encrypted --scheme bfv,ckks,tfhe"

### Key Size
<!-- benchmark_config=" --port 12345 --nb_runs 1 --nb_data 128 --key_length 8192 --nb_operations 8 --folder_prefix test3 --operation add_encrypted --scheme bfv,ckks" -->

### Client Server
python code/he_benchmark.py --client vm1 $benchmark_config
python code/he_benchmark.py --server $benchmark_config
python code/benchmark.py

### Remove rp
rm results_profile/* -rf