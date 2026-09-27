# Ambiente do TCC — carregado automaticamente pelo .bashrc
export TCC=/dados/lucca/tcc-nids-hids

# tudo que cresce vai para /dados, nunca para a home nem para /tmp
export TMPDIR=/dados/lucca/tmp
export XDG_CACHE_HOME=/dados/lucca/.cache
export PIP_CACHE_DIR=/dados/lucca/.cache/pip
export MAMBA_ROOT_PREFIX=/dados/lucca/opt/micromamba
export CONDA_PKGS_DIRS=/dados/lucca/.cache/conda-pkgs
export APPTAINER_CACHEDIR=/dados/lucca/.cache/apptainer
export SINGULARITY_CACHEDIR=/dados/lucca/.cache/apptainer

# binários instalados no espaço do usuário
export PATH=/dados/lucca/opt/bin:$PATH

# cortesia com a máquina compartilhada
alias gentil='nice -n 19 ionice -c 3'
export CAM=$TCC/data/raw/camlds/scenario_3_ssh_puppet/scenario_3_ssh_puppet
export AIT=$TCC/data/raw/ait_ldsv2/russellmitchell
export PCAPS=$TCC/data/raw/camlds_pcaps/scenario_3_ssh_puppet
export ATK=192.42.1.174
