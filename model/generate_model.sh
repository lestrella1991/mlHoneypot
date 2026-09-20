|#!/usr/bin/env bash

# Colors
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
PURPLE='\e[35m'
CYAN='\e[36m'
RESET='\e[0m'

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

sc_print (){
    # Function for reusing print on screen
    echo -e "\n${YELLOW}[+]${RESET}${2} $1${RESET}" >&2
}

sc_print "Chequeando si existe el paquete venv y pip en el equipo" $BLUE

python3 -m pip --version >/dev/null
if [ $? -ne 0 ]; then
    sc_print "Instalando pip..." $RED
    sudo apt update && sudo apt install python3-pip python3-venv -y
else
    python3 -m venv --help >/dev/null
    if [ $? -ne 0 ]; then
    sc_print "Instalando venv..." $RED
    sudo apt update && sudo apt install python3-venv -y
    fi
fi

sc_print "Comprobando si está instalado unzip..." $BLUE

which unzip >/dev/null
if [ $? -ne 0 ]; then
    sc_print "Instalando unzip..." $RED
    sudo apt update && sudo apt install unzip -y
fi

sc_print "Descomprimiendo datasets..." $PURPLE

unzip dataset.zip

sc_print "Creando entorno virtual python..." $PURPLE

python3 -m venv modelo

sc_print "Activando entorno..." $PURPLE

source modelo/bin/activate

sc_print "Instalando librerias..." $PURPLE

pip install -r requirements.txt

sc_print "Generando modelo..." $PURPLE

python3 train_model.py --train UNSW_NB15_training-set.csv --test UNSW_NB15_testing-set.csv --out ../predictor/predict/model/gridsearch_v3.joblib

sc_print "Modelo generado" $PURPLE