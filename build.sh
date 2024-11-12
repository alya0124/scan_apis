#!/bin/bash

# Actualizar repositorios e instalar nmap
sudo apt-get update && sudo apt-get install -y nmap

# Asegurarse de que todas las dependencias de Python estén instaladas
pip install -r requirements.txt

# Iniciar la aplicación Flask (usando Gunicorn, por ejemplo)
gunicorn app:app --bind 0.0.0.0:5000
