# ML Honeypot

![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python)
![Zeek](https://img.shields.io/badge/Network-Zeek-7B2CBF)
![Elastic](https://img.shields.io/badge/Observability-Elastic-005571?logo=elastic)

Proyecto experimental de **honeypot web con clasificación mediante
Machine Learning**, desarrollado para explorar cómo transformar tráfico
observado en información útil para detección, análisis e investigación.

El laboratorio combina clonación de sitios web, generación automática de
configuraciones, captura de telemetría con Zeek, clasificación de
conexiones mediante un modelo de Machine Learning y observabilidad con
Elastic Stack.

> [!IMPORTANT]
> Este repositorio corresponde a una **PoC / laboratorio
> educativo**. No pretende reemplazar controles preventivos, IDS/IPS,
> SIEM, EDR, Threat Intelligence ni el análisis humano. La clasificación
> producida por el modelo debe interpretarse como una señal adicional
> para priorizar e investigar actividad.

## Objetivo

El objetivo es construir un pipeline reproducible que permita:

1.  generar sitios señuelo a partir de aplicaciones web existentes;
2.  desplegarlos como honeypots;
3.  capturar tráfico y actividad de acceso;
4.  transformar la telemetría de red en features utilizables por el
    modelo;
5.  clasificar actividad como normal, sospechosa o maliciosa;
6.  centralizar eventos y resultados en Elastic para su análisis;
7.  utilizar las interacciones observadas como una fuente adicional de
    información para investigación y CTI.

La idea central del proyecto es:

**Honeypot → Telemetría → Clasificación → Observabilidad →
Investigación**

## Arquitectura

La arquitectura actual incorpora tres bloques principales:
**generación**, **procesamiento** y **observabilidad**.

``` mermaid
flowchart LR
    INTERNET((Internet))

    subgraph GEN["Generación"]
        VPN[VPN / NordVPN]
        CRAWLER[Python Crawler]
        CLONES[Clones + configuración]
        VPN --> CRAWLER
        CRAWLER --> CLONES
    end

    subgraph HP["Honeypot"]
        NGINX[Nginx / sitios clonados]
    end

    subgraph PROC["Procesamiento"]
        ZEEK[Zeek]
        ML[Python ML Predictor]
        ZEEK -->|conn.log| ML
    end

    subgraph OBS["Observabilidad"]
        FB[Filebeat]
        LS[Logstash]
        ES[Elasticsearch]
        KB[Kibana]
        FB --> LS --> ES --> KB
    end

    CLONES -->|deploy| NGINX
    INTERNET -->|HTTP/HTTPS| NGINX
    NGINX -->|telemetría| ZEEK
    ZEEK -->|conn.log| FB
    ML -->|clasificación| LS
    NGINX -->|access / sites logs| FB
```

> El diagrama es conceptual. Los nombres exactos de servicios, redes y
> rutas deben consultarse en `docker-compose.yml` y en los archivos de
> configuración del repositorio.

## Flujo del proyecto

### 1. Generación del modelo

**Este paso debe ejecutarse antes de levantar el laboratorio.**

El predictor necesita el artefacto generado durante el entrenamiento. El
repositorio incluye el proceso utilizado para preparar los datos,
entrenar el pipeline y generar el modelo consumido posteriormente por el
contenedor de predicción.

El flujo general es:

``` text
Dataset
   ↓
Preprocesamiento / transformación
   ↓
Entrenamiento
   ↓
Pipeline serializado
   ↓
Predictor
```

Crear primero un entorno virtual de Python:

``` bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
```

Instalar las dependencias correspondientes al generador del modelo:

``` bash
pip install -r requirements.txt
```

Luego ejecutar el script de generación incluido en el repositorio. Por
ejemplo, si se utiliza `generate_model.sh`:

``` bash
chmod +x generate_model.sh
./generate_model.sh
```

> El modelo entrenado puede no estar versionado en Git debido
> a su tamaño. La intención es que pueda **regenerarse a partir del
> proceso de entrenamiento** incluido en el proyecto.

Antes de continuar, verificar que el archivo esperado por el predictor
haya sido generado correctamente.

### 2. Reconocimiento y clonado

El componente `recon` recibe los objetivos definidos para el laboratorio
y ejecuta el proceso de descubrimiento y clonado.

El crawler:

-   descubre recursos y sitios;
-   descarga contenido estático;
-   mantiene una estructura local por sitio;
-   genera configuraciones de Nginx;
-   prepara los clones para su despliegue;
-   puede utilizar una VPN durante el proceso de reconocimiento.

El resultado queda disponible para el servicio encargado de publicar los
sitios señuelo.

### 3. Exposición del honeypot

Nginx publica los sitios clonados y registra la actividad recibida.

Para exponer los clones mediante nombres distintos a los dominios
originales, por ejemplo:

``` text
dev.example.com
stage.example.com
```

deben modificarse los `server_name` generados para cada sitio y crear
los registros DNS correspondientes apuntando a la infraestructura del
honeypot.

No es necesario volver a ejecutar todo el crawler únicamente por un
cambio de nombre si los clones y configuraciones ya fueron generados.
Después de modificar las configuraciones, validar Nginx y
recargar/reiniciar el servicio según corresponda.

### 4. Captura y procesamiento

Zeek observa el tráfico del honeypot y genera telemetría de red,
principalmente `conn.log`.

El predictor transforma los campos relevantes al mismo esquema utilizado
durante el entrenamiento y ejecuta la clasificación mediante el pipeline
serializado.

La clasificación generada se utiliza como **señal de detección**, no
como veredicto aislado.

### 5. Observabilidad

Los eventos se envían hacia Elastic Stack.

El pipeline permite mantener, entre otros:

-   telemetría de Zeek;
-   logs de acceso de los sitios clonados;
-   resultados de clasificación;
-   IP de origen;
-   IP y puerto de destino;
-   bytes y paquetes;
-   protocolo/transporte;
-   timestamp;
-   etiquetas de clasificación.

Kibana permite visualizar actividad, fuentes observadas y distribución
de las clasificaciones.

## Estructura del repositorio

La estructura puede variar ligeramente según la versión del laboratorio,
pero conceptualmente contiene:

``` text
mlHoneypot/
├── data/                  # Datos utilizados por el laboratorio/modelo
├── elasticsearch/         # Configuración de Elasticsearch
├── generated/             # Configuración generada automáticamente
│   └── sites/             # Virtual hosts de los sitios clonados
├── kibana/                # Configuración / objetos de Kibana
├── nordvpn/               # Configuración asociada a VPN
├── pcap/                  # Capturas de tráfico, si se utilizan
├── predictor/             # Predictor y modelo generado
├── recon/                 # Crawler / reconocimiento / generación
├── sites/                 # Contenido de los sitios clonados
├── tor/                   # Componentes opcionales relacionados
├── recon-output/          # Sitios activos detectados
├── docker-compose.yml
├── filebeat.yml
├── logstash.conf
├── env.example
└── README.md
```

## Componentes

  -----------------------------------------------------------------------
  Componente                          Función
  ----------------------------------- -----------------------------------
  **Python**                          Entrenamiento, transformación,
                                      crawler y clasificación

  **Docker Compose**                  Orquestación del laboratorio

  **Nginx**                           Publicación de los sitios clonados

  **Zeek**                            Generación de telemetría de red

  **Predictor ML**                    Clasificación de conexiones

  **Filebeat**                        Recolección y envío de eventos

  **Logstash**                        Parsing, normalización y routing

  **Elasticsearch**                   Almacenamiento e indexación

  **Kibana**                          Visualización y análisis

  **NordVPN**                         Salida opcional mediante VPN
                                      durante tareas de reconocimiento
  -----------------------------------------------------------------------

## Requisitos

Para ejecutar el laboratorio se necesita:

-   Linux. El proyecto fue trabajado y probado sobre **Ubuntu Server**;
    no se busca compatibilidad multiplataforma.
-   Python 3.
-   Soporte para `venv`.
-   Paquetes Python definidos por el proyecto.
-   Docker.
-   Docker Compose.
-   Espacio suficiente para imágenes, índices, clones y datasets.
-   Acceso de red hacia los objetivos utilizados durante el proceso de
    generación.
-   Token/credenciales de NordVPN **solo si se habilita el componente
    VPN**.

Comprobar Python y `venv`:

``` bash
python3 --version
python3 -m venv --help
```

En Ubuntu, si `venv` no está instalado:

``` bash
sudo apt update
sudo apt install python3-venv
```

Comprobar Docker:

``` bash
docker --version
docker compose version
```

## Configuración

### 1. Clonar el repositorio

``` bash
git clone <REPOSITORY_URL>
cd mlHoneypot
```

### 2. Generar el modelo

Ejecutar **antes de `docker compose up`** el proceso explicado en
[Generación del modelo](#1-generación-del-modelo).

### 3. Crear el archivo de entorno

Utilizar `env.example` como referencia:

``` bash
cp env.example .env
```

Completar únicamente las variables necesarias para la configuración
utilizada.

Ejemplo conceptual:

``` env
#Dominio
TARGET_DOMAIN=domain.to.clone

# VPN opcional
NORDVPN_TOKEN=change_me
```

> \[!CAUTION\] 
> Los nombres anteriores son ilustrativos. Utilizar como
> referencia definitiva `env.example` y `docker-compose.yml`.

> \[!CAUTION\]
> No publiques `.env`, tokens, contraseñas, certificados
> privados ni credenciales de servicios externos.

### 4. Permisos

Algunos contenedores se ejecutan con usuarios no privilegiados y
escriben sobre directorios montados desde el host.

Verificar permisos antes de levantar el entorno:

``` bash
ls -la
```

Si se modifican propietarios/permisos, hacerlo únicamente sobre los
directorios que realmente necesiten escritura. Evitar como solución
genérica:

``` bash
chmod -R 777 .
```

### 5. Levantar el entorno

``` bash
docker compose build
docker compose up -d
```

Verificar el estado:

``` bash
docker compose ps
```

Consultar logs:

``` bash
docker compose logs -f
```

O un servicio concreto:

``` bash
docker compose logs -f recon
```

## DNS y publicación de clones

Para publicar los honeypots durante una prueba controlada se recomienda
**no utilizar directamente los nombres de producción clonados**.

Ejemplo:

``` text
Original:
avion.example.com

Honeypot:
dev-avion.honeypot.example.com
```

o una convención equivalente definida para el laboratorio.

El proceso recomendado es:

1.  elegir los nombres que utilizarán los honeypots;
2.  modificar `server_name` en las configuraciones generadas;
3.  crear los registros DNS correspondientes;
4.  validar la configuración;
5.  recargar Nginx;
6.  verificar que el acceso directo por IP no exponga accidentalmente un
    sitio clonado.

### Evitar servir un clon por acceso directo a la IP

Se recomienda configurar un `default_server` que descarte solicitudes
que no coincidan con un `server_name` esperado.

Por ejemplo:

``` nginx
server {
    listen 80 default_server;
    server_name _;

    return 444;
}
```

El código `444` es una extensión de Nginx que cierra la conexión sin
enviar una respuesta HTTP.

> \[!IMPORTANT\]
> El `default_server` debe existir en el **punto de
> entrada que recibe la conexión externa**. Si existe un reverse proxy
> delante del Nginx que sirve los clones, aplicar el control en el
> listener expuesto a Internet, no únicamente en un virtual host
> interno.

Antes de recargar:

``` bash
nginx -t
```

En Docker, según el servicio utilizado:

``` bash
docker compose exec <nginx-service> nginx -t
docker compose restart <nginx-service>
```

## Logs y datos

El laboratorio trabaja con dos fuentes especialmente relevantes.

### Telemetría de Zeek

`conn.log` proporciona información como:

``` text
source.ip
source.port
destination.ip
destination.port
source.bytes
destination.bytes
source.packets
destination.packets
network.transport
```

Estos datos son transformados al esquema utilizado por el modelo.

### Logs de los sitios

Nginx genera logs de acceso de los clones. Estos eventos permiten
complementar la telemetría de red con información HTTP y actividad
observada sobre cada honeypot.

Ambas fuentes pueden ser enviadas hacia Elastic mediante
Filebeat/Logstash.

## Clasificación

El modelo se utiliza para priorizar conexiones observadas.

Dependiendo del pipeline y del umbral configurado, una conexión puede
terminar representada como:

``` text
normal
suspicious
malicious
```

> \[!IMPORTANT\]
> La probabilidad o etiqueta generada por el modelo no
> constituye por sí sola evidencia suficiente para atribuir una
> actividad a un atacante ni reemplaza una investigación.

Una detección puede enriquecerse posteriormente con información
adicional como ASN, reputación, geolocalización aproximada, histórico e
indicadores relacionados.

## Dashboard

El dashboard utilizado durante la PoC puede mostrar, por ejemplo:

-   cantidad total de requests;
-   cantidad de IP de origen;
-   IP sospechosas;
-   IP maliciosas;
-   actividad a lo largo del tiempo;
-   distribución de clasificación;
-   principales IP de origen;
-   principales puertos de destino.

El objetivo no es únicamente almacenar logs, sino transformar la
actividad capturada en información consultable.

## Seguridad

Este proyecto despliega servicios diseñados para recibir actividad
potencialmente hostil.

Recomendaciones mínimas:

-   ejecutarlo en infraestructura aislada;
-   no reutilizar credenciales reales;
-   no almacenar secretos en Git;
-   limitar conectividad desde el honeypot hacia redes internas;
-   revisar los puertos publicados por Docker;
-   impedir que el acceso directo por IP exponga un clon;
-   separar los dominios del laboratorio de servicios productivos;
-   aplicar límites de recursos y almacenamiento;
-   revisar periódicamente los logs y el crecimiento de Elasticsearch;
-   mantener Docker, imágenes y dependencias actualizadas.

## Limitaciones

### El clonado estático tiene limitaciones

Aplicaciones modernas pueden depender de JavaScript, APIs,
autenticación, CORS, contenido dinámico y servicios externos. Un clon
estático puede reproducir correctamente la superficie visual sin
reproducir toda la lógica de la aplicación original.

### El modelo depende de los datos de entrenamiento

El comportamiento del clasificador está condicionado por el dataset, las
features seleccionadas, el preprocesamiento y el escenario para el que
fue entrenado.

Un buen resultado sobre el conjunto utilizado durante el desarrollo no
implica automáticamente la misma capacidad de generalización frente a
cualquier tráfico real.

### La clasificación no reemplaza la investigación

El modelo ayuda a reducir volumen y priorizar actividad. Una
clasificación debe correlacionarse con el resto de la evidencia
disponible.

### La atribución de IP puede depender de la arquitectura

Reverse proxies, NAT y redes Docker pueden provocar que Zeek o Nginx
observen una dirección interna en lugar de la IP pública original si no
se preserva correctamente la información de origen.

## De honeypot a inteligencia

El objetivo final del laboratorio no es solamente generar alertas.

Cada interacción observada puede transformarse en datos propios sobre la
actividad dirigida contra la infraestructura señuelo. Al combinar
telemetría, clasificación, contexto y análisis, esos datos pueden
convertirse en una fuente adicional para investigación y procesos de
Cyber Threat Intelligence.

**Cada interacción puede convertirse en información sobre las amenazas
que nos buscan.**

## Disclaimer

Este repositorio fue creado con fines **educativos, experimentales y de
demostración**.

Utilizá el crawler, los clones y los componentes de reconocimiento
únicamente sobre infraestructura propia o sobre sistemas para los que
tengas autorización explícita.

El proyecto no garantiza detección completa de actividad maliciosa y no
debe utilizarse como único mecanismo de seguridad.
