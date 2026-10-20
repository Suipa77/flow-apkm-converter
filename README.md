# APKM Compatibility Converter (Android TV 7.1–8.0)

Herramienta personal, escrita en Python, que reempaqueta un archivo `.apkm` (paquete con splits) en un único `.apk` ajustado para funcionar en dispositivos Android TV antiguos (Android 7.1–8.0). Fue pensada para una app de TV compatible con Android 8.1+ cuyo paquete original no instala en esos equipos.

> **Este repositorio contiene únicamente el script.** No incluye, aloja ni distribuye ningún APK, APKM, librería, recurso ni código de terceros.

## Aviso legal importante

- Proyecto **independiente y no oficial**. No tiene relación, aval ni patrocinio de Flow, Personal, Telecom Argentina ni de ninguna otra empresa. Todas las marcas pertenecen a sus respectivos titulares y se mencionan únicamente para indicar compatibilidad.
- **Traé tu propio archivo.** Solo debés procesar paquetes que hayas obtenido de forma legítima y sobre los que tengas derecho de uso (por ejemplo, una app que tenés habilitada con tu propio servicio o suscripción).
- **No redistribuyas** los APK resultantes. El archivo generado es una obra derivada del software original y su difusión puede infringir derechos de autor y los términos de uso de la aplicación.
- **No elude** cuentas, suscripciones, pagos, DRM ni controles de acceso. El script no los modifica ni debe usarse con ese fin.
- Revisá los términos y condiciones de la aplicación original y la legislación de tu país antes de usar la herramienta. El uso es **bajo tu exclusiva responsabilidad**.
- Si sos titular de derechos y considerás que este proyecto te afecta, abrí un *issue* y se evaluará retirarlo de inmediato.

## Requisitos

- Python 3.6+
- Java JDK (`keytool`)
- `apksigner` (Android SDK Build-Tools)
  - Ubuntu/Debian: `sudo apt install apksigner`
  - macOS: `brew install --cask android-platform-tools`

## Uso

```bash
python3 convert_flow_apkm.py ruta/al/archivo.apkm
```

Si no indicás ruta, el script busca un `.apkm` en la misma carpeta. El resultado se guarda junto al `.apkm` de entrada.

## Qué hace (resumen técnico)

1. Extrae el paquete `.apkm` (`base.apk` y splits).
2. Ajusta los DEX a un formato aceptado por Android 7.1–8.0 (versión 038 → 037).
3. Ajusta los parámetros de compatibilidad del `AndroidManifest.xml`.
4. Unifica recursos del split de densidad (xhdpi) en `resources.arsc`.
5. Incorpora las librerías nativas ARM incluidas en el propio paquete.
6. Ensambla el APK y lo firma con una clave de debug local, generada en tu equipo.

El APK queda firmado con una clave distinta de la original, por lo que no se actualiza sobre la app de la tienda y no es un reemplazo oficial.

## Limitaciones

- Sin garantías: puede no funcionar con todas las versiones de la app ni con todos los dispositivos.
- No se brinda soporte para obtener paquetes ni para usos que infrinjan términos de terceros.

## Licencia

El código de este repositorio se publica bajo licencia MIT (ver [LICENSE](LICENSE)). La licencia cubre solo el script, no el software de terceros que procese.
