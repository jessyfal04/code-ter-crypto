rm results_profile/* -rf
benchmark_config="--operation add_encrypted --nb_runs 5 --msg_size 4,6,8,10,12 --msg_nb 16"

python code/phe_benchmark.py --client vm1 $benchmark_config
python code/phe_benchmark.py --server $benchmark_config