import argparse
import logging
import subprocess
import requests
import time

# Configuración de logging para Actividad 3
timestamp_format = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    filename="actividad3.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt=timestamp_format
)

# Act 1: Ejecutar PowerShell para obtener IPs activas
def ex_ps():
    try:
        resultado = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "IPsActivas.ps1"],
            capture_output=True, text=True, check=True
        )
        print("PowerShell ejecutado correctamente.")
        logging.info("PowerShell ejecutado correctamente.")
    except Exception as e:
        print(f"Error ejecutando PowerShell: {e}")
        logging.error(f"Error ejecutando PowerShell: {e}")

# Act 1: Leer IPs desde el archivo generado por PowerShell
def obtener_ips_archivo():
    ips = []
    try:
        with open("ConexionesIPs.txt", "r", encoding="utf-16") as archivo:
            for line in archivo:
                ip = line.strip()
                if ip:
                    ips.append(ip)
        logging.info(f"IPs obtenidas del archivo: {ips}")
        return ips
    except FileNotFoundError:
        msg = "El archivo 'ConexionesIPs.txt' no fue encontrado."
        print(msg)
        logging.error(msg)
        return []
    except Exception as e:
        print(f"Ocurrió un error diferente: {e}")
        logging.error(f"Error al leer archivo de IPs: {e}")
        return []

# Act 2: Checar IP en AbuseIPDB
def checar_ip(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        if "data" in data:
            score = data["data"]["abuseConfidenceScore"]
            if score == 0:
                return f"{ip}: No está reportada como maliciosa."
            elif score < 50:
                return f"{ip}: Tiene algunos reportes. Nivel de sospecha: {score}"
            else:
                return f"{ip}: ¡POTENCIALMENTE MALICIOSA! (Nivel de sospecha: {score})"
        return f"{ip}: Error al consultar la API"
    except Exception as e:
        return f"{ip}: Error -> {e}"

# Act 4: Argumentos desde línea de comandos con ayuda mejorada
def parsear_args():
    parser = argparse.ArgumentParser(
        description="Verificar IPs con AbuseIPDB y PowerShell",
        epilog="Ejemplos:\n  python actividad3.py -k AQUI_ESCRIBE_TU_API_KEY\n  python actividad3.py -k AQUI_ESCRIBE_TU_API_KEY -i 8.8.8.8 1.1.1.1 -n 2"
,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-i', '--ips', nargs='+', help='Lista de IPs separadas por espacio',
        default=None
    )
    parser.add_argument(
        '-k', '--key', required=True, help='API Key de AbuseIPDB'
    )
    parser.add_argument(
        '-n', '--number', type=int, default=3,
        help='Número máximo de IPs a verificar (por defecto 3)'
    )
    return parser.parse_args()

# Act 3 y 4: Main con logging, uso de argparse y verificación
def main():
    args = parsear_args()
    api_key = args.key
    max_ips = args.number

    logging.info("=== Inicio de ejecución ===")

    if args.ips:
        ips = args.ips
        logging.info(f"IPs recibidas por argumento: {ips}")
    else:
        print("[*] Ejecutando script de PowerShell para obtener IPs...")
        ex_ps()
        print("[*] Leyendo lista de IPs desde archivo...")
        ips = obtener_ips_archivo()

    print(f"IPs a verificar: {ips}")
    logging.info(f"IPs a verificar: {ips}")

    print(f"\n[*] Verificando hasta {max_ips} IPs con AbuseIPDB...")
    logging.info(f"Iniciando verificación de hasta {max_ips} IPs")

    count = 0
    for ip in ips:
        if count >= max_ips:
            break
        resultado = checar_ip(ip, api_key)
        print(resultado)
        logging.info(resultado)
        count += 1
        time.sleep(1.5)

    logging.info("=== Fin de ejecución ===\n")

if __name__ == "__main__":
    main()

