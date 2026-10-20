# Flow APKM Converter

Convierte un `.apkm` de Flow (Android 8.1+) en un `.apk` instalable en Android TV 7.1–8.0 (dispositivos antiguos).

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

Si no indicás ruta, el script busca un `.apkm` en la misma carpeta.

Salida: `FlowATV_<versión>_Android8.apk`, junto al `.apkm`.

## Qué hace

1. Extrae el APKM (`base.apk` y splits).
2. Parchea los DEX (versión 038 → 037).
3. Parchea `AndroidManifest.xml`.
4. Fusiona `resources.arsc` con el split xhdpi.
5. Agrega las librerías nativas ARM (arm64-v8a / armeabi-v7a).
6. Ensambla el APK y lo firma con `apksigner` (clave de debug).

## Aviso legal

Proyecto independiente, sin afiliación con Flow. No incluye ni distribuye APK/APKM. Usalo solo con archivos que tengas derecho a usar. Se ofrece "tal cual", sin garantías.

## Licencia

MIT. Ver [LICENSE](LICENSE).
