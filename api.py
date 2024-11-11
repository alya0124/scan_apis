from flask import Flask, jsonify, request
import nmap
import psycopg2
import json
from psycopg2 import sql

app = Flask(__name__, static_folder='static', template_folder='templates')

DATABASE_URL = "postgresql://scan_user:your_password@localhost:5432/scan_db"
nm = nmap.PortScanner()

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            hostname TEXT,
            state TEXT,
            ports TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

@app.route('/scan', methods=['GET', 'POST'])
def scan_ip():
    datos = request.get_json()
    ip = datos.get('ip', '')
    ports = datos.get('ports', '1-1000')

    scan_result = {}

    if not ip:
        return jsonify({'error': 'No IP provided'}), 400

    try:
        nm.scan(ip, ports)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    for host in nm.all_hosts():
        scan_result[host] = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'ports': []
        }
        for protocol in nm[host].all_protocols():
            ports = []
            for port in nm[host][protocol].keys():
                port_info = {
                    'port': port,
                    'state': nm[host][protocol][port]['state']
                }
                ports.append(port_info)
            scan_result[host]['ports'] = ports

    return jsonify(scan_result), 200

@app.route('/insert-scan', methods=['POST'])
def insert_scan():
    data = request.get_json()
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'error': 'IP no proporcionada'}), 400

    hostname = data.get('hostname', '')
    state = data.get('state', '')
    ports = json.dumps(data.get('ports', ''))

    if not hostname or not state or not ports:
        return jsonify({'error': 'Datos incompletos para la IP'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO scans (ip, hostname, state, ports) 
        VALUES (%s, %s, %s, %s)
    ''', (ip, hostname, state, ports))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Datos insertados correctamente'}), 200

@app.route('/get-scans', methods=['GET'])
def get_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans')
    rows = cursor.fetchall()
    
    scans = []
    for row in rows:
        scans.append({
            'id': row[0],
            'ip': row[1],
            'hostname': row[2],
            'state': row[3],
            'ports': row[4]  
        })

    conn.close()
    return jsonify(scans)

@app.route('/update-scan', methods=['PUT'])
def update_scan():
    data = request.get_json()
    scan_id = data.get('id')
    
    if not scan_id:
        return jsonify({'error': 'ID no proporcionado'}), 400
    
    ip = data.get('ip', '')
    hostname = data.get('hostname', '')
    state = data.get('state', '')
    ports = json.dumps(data.get('ports', ''))
    
    if not ip or not hostname or not state or not ports:
        return jsonify({'error': 'Datos incompletos para la actualización'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE scans
        SET ip = %s, hostname = %s, state = %s, ports = %s
        WHERE id = %s
    ''', (ip, hostname, state, ports, scan_id))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Registro actualizado correctamente'}), 200

@app.route('/delete-scan', methods=['DELETE'])
def delete_scan():
    data = request.get_json()
    scan_id = data.get('id')

    if not scan_id:
        return jsonify({'error': 'ID no proporcionado'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM scans WHERE id = %s', (scan_id,))
    row = cursor.fetchone()
    
    if not row:
        return jsonify({'error': 'ID no encontrado'}), 404

    cursor.execute('DELETE FROM scans WHERE id = %s', (scan_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Registro eliminado correctamente'}), 200

if __name__ == '__main__':
    create_table()  
    app.run(debug=True, port=8080)
