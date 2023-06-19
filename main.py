import nmap
import socket
import requests #Aún no es usada esta librería, pronto se necesitara para otra parte del codigo...


print("""

╔═══╗────────╔╗─────╔═══╦═══╦═══╗╔═══╗────╔╗─╔════╗────╔╗
║╔═╗║───────╔╝╚╗────║╔═╗║╔═╗║╔═╗║║╔═╗║───╔╝╚╗║╔╗╔╗║────║║
║╚══╦══╦═╦╦═╩╗╔╬══╦═╣╚═╝╠╝╔╝║╚═╝║║╚═╝╠══╦╩╗╔╝╚╝║║╠╩═╦══╣║
╚══╗║╔═╣╔╬╣╔╗║║║║═╣╔╩══╗╠═╝╔╣╔═╗║║╔══╣╔╗║╔╣║───║║║╔╗║╔╗║║
║╚═╝║╚═╣║║║╚╝║╚╣║═╣║╔══╝║║╚═╣╚═╝║║║──║╚╝║║║╚╗──║║║╚╝║╚╝║╚╗
╚═══╩══╩╝╚╣╔═╩═╩══╩╝╚═══╩═══╩═══╝╚╝──╚══╩╝╚═╝──╚╝╚══╩══╩═╝
──────────║║
──────────╚╝
Github: 

Opciones: 
[1]: Obtener dirección IP de un sitio web...
[2]: Escanear una dirección IP para obtener los puertos abiertos...
[3]: Obtener la dirección IP privada de mi dispositivo...
[4]: Ver host de una dirección IP...
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
    print("En desarrollo...")
else:
    print("Null")
