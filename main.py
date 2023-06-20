import nmap
import socket
import requests 
from scapy.all import ARP, Ether, srp


print("""

╔═══╗────────╔╗─────╔═══╦═══╦═══╗╔═══╗────╔╗─╔════╗────╔╗
║╔═╗║───────╔╝╚╗────║╔═╗║╔═╗║╔═╗║║╔═╗║───╔╝╚╗║╔╗╔╗║────║║
║╚══╦══╦═╦╦═╩╗╔╬══╦═╣╚═╝╠╝╔╝║╚═╝║║╚═╝╠══╦╩╗╔╝╚╝║║╠╩═╦══╣║
╚══╗║╔═╣╔╬╣╔╗║║║║═╣╔╩══╗╠═╝╔╣╔═╗║║╔══╣╔╗║╔╣║───║║║╔╗║╔╗║║
║╚═╝║╚═╣║║║╚╝║╚╣║═╣║╔══╝║║╚═╣╚═╝║║║──║╚╝║║║╚╗──║║║╚╝║╚╝║╚╗
╚═══╩══╩╝╚╣╔═╩═╩══╩╝╚═══╩═══╩═══╝╚╝──╚══╩╝╚═╝──╚╝╚══╩══╩═╝
──────────║║
──────────╚╝
Github: https://github.com/Scripter928/Scripter928-Port-Tool

Opciones: 
[1]: Obtener dirección IP de un sitio web...
[2]: Escanear una dirección IP para obtener los puertos abiertos...
[3]: Obtener la dirección IP privada de mi dispositivo...
[4]: Obtener información de una dirección IP... (Ej: Companía, ciudad, país, etc...)
[5]: Ver toda IP y MAC Adress privada de los dispositivos conectados a nuestra red...
""")
opciones = input("Opción: ")

if opciones == "1":
    name_dom = input('Importa el nombre del dominio: ')

    dominio = name_dom

    ip = socket.gethostbyname(dominio)

    print("IP:", ip)

elif opciones == "2":
    #Input para seleccionar la ip
    ip = input('IP Para realizar el escaneo: ')

    #Generar variable del escaneo
    scan = nmap.PortScanner()

    #Escanear los puertos
    scan.scan(ip, '22-443')

    #Print de resultados
    for host in scan.all_hosts():
        print('Estado:', scan[host].state())
        for proto in scan[host].all_protocols():
            print('Protocolo:', proto)
            lport = scan[host][proto].keys()
            for port in lport:
                print('Puerto:', port, 'Estado:', scan[host][proto][port]['state'])

elif opciones == "3":
    print("IP: "+socket.gethostbyname(socket.gethostname()))

elif opciones == "4":
    ip_adress = input("Selecciona una dirección IP: ")
    respuesta = requests.get(f"https://ipapi.co/{ip_adress}/json/").json()

    city = respuesta.get("city", "unkown")
    pais = respuesta.get("country_name", "unkown")
    codigo_postal = respuesta.get("postal", "unkown")
    org = respuesta.get("org", "unkown")

    print(f"""
País: {pais}
Ciudad: {city}
Código postal: {codigo_postal}
Companía: {org}""")

elif opciones == "5":

    """
    Parte de este código fue sacado por la ia de Clyde (Discord)
    """
    print("-Ejemplo: 192.168.0.0")
    valor = input("IP privada: ")
    # Crea un paquete ARP de broadcast
    arp = ARP(pdst=f"{valor}/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Envía el paquete y obtiene una lista de respuestas
    result = srp(packet, timeout=3, verbose=0)[0]

    # Imprime las direcciones IP y MAC de los dispositivos encontrados
    print("Dispositivos conectados a tu red:")
    print("IP\t\t\tMAC Address")
    for sent, received in result:
        print(f"{received.psrc}\t\t{received.hwsrc}")
else:
    print("Null")
