import logging
import subprocess
import requests
import time

# Configuración de logging para Actividad 6
timestamp_format = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    filename="actividad6_output.log",  # Cambiado a actividad6_output.log
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt=timestamp_format
)

def ex_ps():
    try:
        resultado = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", "IPsActivas.ps1"],
            capture_output=True, text=True, check=True
        )
        logging.info("PowerShell ejecutado correctamente.")
        logging.debug(f"Salida PowerShell: {resultado.stdout}")
    except Exception as e:
        logging.error(f"Error ejecutando PowerShell: {e}")

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
        logging.error(msg)
        return []
    except Exception as e:
        logging.error(f"Error al leer archivo de IPs: {e}")
        return []

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

def main():
    logging.info("***Inicio del Log***")

    ex_ps()

    ips = obtener_ips()
    logging.info(f"IPs encontradas: {ips}")

    logging.info("Iniciando verificación de IPs contra AbuseIPDB")

    count = 0
    for ip in ips:
        if count == 3:
            break
        resultado = checar_ip(ip)
        logging.info(resultado)
        count += 1
        time.sleep(1.5)

    logging.info("***Fin del Log***\n")
    logging.shutdown()

if __name__ == "__main__":
    main()
