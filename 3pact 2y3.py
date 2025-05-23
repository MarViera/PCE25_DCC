import logging
import subprocess
import requests
import json
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
        logging.debug(f"Salida PowerShell: {resultado.stdout}")
    except Exception as e:
        print("Error ejecutando PowerShell:")
        print(e.stderr if hasattr(e, 'stderr') else e)
        logging.error(f"Error ejecutando PowerShell: {e}")

# Act 1: Leer IPs desde el archivo generado por PowerShell
def obtener_ips():
    ips = []
    try:
        with open("ConexionesIPs.txt", "r", encoding="utf-16") as archivo:
            for line in archivo:
                ip = line.strip()
                if ip:
                    ips.append(ip)
        logging.info(f"IPs obtenidas: {ips}")
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
def checar_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': "609313b4676d04e45cc076fd79cde6015c9599ac6c38a1bf4c91bd8bd0859afb5304f59c381abd13"
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        data = response.json()
        if "data" in data:
            reportes = data["data"]["totalReports"]
            abuser = data["data"]["abuseConfidenceScore"]
            if abuser == 0:
                return f"{ip}: No está reportada como maliciosa."
            elif abuser < 50:
                return f"{ip}: Tiene algunos reportes. Nivel de sospecha: {abuser}"
            else:
                return f"{ip}: ¡POTENCIALMENTE MALICIOSA! (Nivel de sospecha: {abuser})"
        else:
            return f"{ip}: Error al consultar la API"
    except Exception as e:
        return f"{ip}: Error -> {str(e)}"

# Act 3: Main con logging de resultados
def main():
    logging.info("***Inicio del Log***")

    print("[*] Ejecutando script de PowerShell...")
    ex_ps()

    print("[*] Leyendo lista de IPs...")
    ips = obtener_ips()
    print(f"IPs encontradas: {ips}")

    print("\n[*] Verificando hasta 3 IPs con AbuseIPDB...")
    logging.info("Iniciando verificación de IPs contra AbuseIPDB")

    count = 0
    for ip in ips:
        if count == 3:
            break
        resultado = checar_ip(ip)
        print(resultado)
        logging.info(resultado)
        count += 1
        time.sleep(1.5)

    logging.info("***Fin del Log***\n")

if __name__ == "__main__":
    main()

