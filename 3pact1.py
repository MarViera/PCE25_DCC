import subprocess
import requests
import json
import time

def ex_ps():
    try:
        resultado = subprocess.run( ["powershell", "-ExecutionPolicy", "Bypass", "-File", "IPsActivas.ps1"],
            capture_output=True, text=True, check=True
        )
        print(" PowerShell ejecutado correctamente.")
        print("Salida PowerShell:", resultado.stdout)
    except Exception as e:
        print(" Error ejecutando PowerShell:")
        print(e.stderr)

def obtener_ips():
    ips = []
    try:
        with open("ConexionesIPs.txt", "r", encoding="utf-16") as archivo:
            for line in archivo:
                ips.append(line.strip())
        return ips
    except FileNotFoundError:
        print(" El archivo 'ConexionesIPs.txt' no fue encontrado.")
        return []


def checar_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': 'TU_API_KEY_AQUI'  # <--- REEMPLAZA CON TU PROPIA API KEY
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

def main():
    print("[*] Ejecutando script de PowerShell...")
    ex_ps()

    print("[*] Leyendo lista de IPs...")
    ips = obtener_ips()
    print("IPs encontradas:", ips)

 

if __name__ == "__main__":
    main()
