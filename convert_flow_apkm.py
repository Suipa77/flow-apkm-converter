#!/usr/bin/env python3
"""
convert_flow_apkm.py
====================
Convierte un APKM de FlowATV (Android 8.1+) a un APK compatible con Android 8.0.

USO:
    python3 convert_flow_apkm.py <archivo.apkm>

    O colocar el script en la misma carpeta que el .apkm y ejecutar:
    python3 convert_flow_apkm.py

REQUISITOS:
    - Python 3.6+
    - Java JDK instalado (java, keytool)
    - apksigner en el PATH  (parte de Android SDK Build-Tools, o instalado via apt/brew)

    En Ubuntu/Debian:
        sudo apt install apksigner

    En macOS con Homebrew:
        brew install --cask android-platform-tools

SALIDA:
    FlowATV_<version>_Android8.apk  (en la misma carpeta que el .apkm)
"""

import os
import sys
import struct
import zlib
import hashlib
import zipfile
import shutil
import tempfile
import subprocess
import glob

# ─────────────────────────────────────────────
# UTILIDADES ZIP
# ─────────────────────────────────────────────

def deflate(data):
    c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()

def make_align_extra(pos, name_len, align):
    """Genera el extra field con tag 0xD935 para alinear datos a `align` bytes."""
    base = pos + 30 + name_len
    needed = (align - (base + 4) % align) % align
    if needed == 0 and base % align == 0:
        return b''
    if needed == 0:
        needed = align
    extra = struct.pack('<HH', 0xD935, needed) + b'\x00' * needed
    assert (pos + 30 + name_len + len(extra)) % align == 0, "alignment error"
    return extra

def write_zip_entry(out_f, entries, name_str, data, store=False, align=4):
    """Escribe una entrada al archivo ZIP abierto out_f."""
    name = name_str.encode('utf-8')
    compressed = data if store else deflate(data)
    compress_type = 0 if store else 8
    crc = zlib.crc32(data) & 0xFFFFFFFF
    header_offset = out_f.tell()

    if store and align > 4:
        extra = make_align_extra(header_offset, len(name), align)
    else:
        base = header_offset + 30 + len(name)
        extra = b'\x00' * ((align - base % align) % align)

    lh  = b'PK\x03\x04'
    lh += struct.pack('<H', 20)          # version needed
    lh += struct.pack('<H', 0)           # flags
    lh += struct.pack('<H', compress_type)
    lh += struct.pack('<HH', 0, 0)       # mod time, date
    lh += struct.pack('<I', crc)
    lh += struct.pack('<I', len(compressed))
    lh += struct.pack('<I', len(data))
    lh += struct.pack('<H', len(name))
    lh += struct.pack('<H', len(extra))
    out_f.write(lh + name + extra + compressed)
    entries.append({
        'name': name, 'compress_type': compress_type, 'crc': crc,
        'csz': len(compressed), 'usz': len(data), 'header_offset': header_offset
    })

def write_zip_central_directory(out_f, entries):
    """Escribe el directorio central y el EOCD."""
    cd_offset = out_f.tell()
    for e in entries:
        cd  = b'PK\x01\x02'
        cd += struct.pack('<HH', 20, 20)
        cd += struct.pack('<H', 0)
        cd += struct.pack('<H', e['compress_type'])
        cd += struct.pack('<HH', 0, 0)
        cd += struct.pack('<I', e['crc'])
        cd += struct.pack('<I', e['csz'])
        cd += struct.pack('<I', e['usz'])
        cd += struct.pack('<H', len(e['name']))
        cd += struct.pack('<HH', 0, 0)   # extra, comment
        cd += struct.pack('<H', 0)        # disk start
        cd += struct.pack('<HI', 0, 0)   # int/ext attr
        cd += struct.pack('<I', e['header_offset'])
        out_f.write(cd + e['name'])
    cd_size = out_f.tell() - cd_offset
    eocd  = b'PK\x05\x06' + b'\x00' * 4
    eocd += struct.pack('<HH', len(entries), len(entries))
    eocd += struct.pack('<II', cd_size, cd_offset)
    eocd += b'\x00\x00'
    out_f.write(eocd)


# ─────────────────────────────────────────────
# PARCHE DEX
# ─────────────────────────────────────────────

def patch_dex(data):
    """Downgrade DEX versión 038 → 037 y recalcula checksums."""
    data = bytearray(data)
    if data[:4] != b'dex\n':
        return bytes(data)
    if data[4:7] == b'037':
        return bytes(data)
    data[4:7] = b'037'
    data[7:8] = b'\x00'
    sha1 = hashlib.sha1(bytes(data[32:])).digest()
    data[12:32] = sha1
    checksum = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', data, 8, checksum)
    return bytes(data)


# ─────────────────────────────────────────────
# PARCHE ANDROIDMANIFEST (AXML BINARIO)
# ─────────────────────────────────────────────

def patch_manifest(manifest_data):
    """
    Modifica el AndroidManifest.xml binario (AXML):
    - Remueve atributos: requiredSplitTypes, splitTypes, extractNativeLibs
    - Cambia minSdkVersion de 27 a 25
    - Remueve 5 elementos <meta-data> de splits de Play Store
    """
    data = bytearray(manifest_data)

    sp_pos = 8
    sp_header_size = struct.unpack('<H', data[sp_pos+2:sp_pos+4])[0]
    sp_chunk_size  = struct.unpack('<I', data[sp_pos+4:sp_pos+8])[0]
    sp_count       = struct.unpack('<I', data[sp_pos+8:sp_pos+12])[0]
    sp_str_start   = struct.unpack('<I', data[sp_pos+20:sp_pos+24])[0]

    offsets_base = sp_pos + sp_header_size
    offsets = [struct.unpack('<I', data[offsets_base+i*4:offsets_base+i*4+4])[0]
               for i in range(sp_count)]

    def get_string(idx):
        if idx < 0 or idx >= sp_count:
            return ''
        abs_pos = sp_pos + sp_str_start + offsets[idx]
        slen = struct.unpack('<H', data[abs_pos:abs_pos+2])[0]
        if slen & 0x8000:
            slen = ((slen & 0x7fff) << 16) | struct.unpack('<H', data[abs_pos+2:abs_pos+4])[0]
            abs_pos += 4
        else:
            abs_pos += 2
        return data[abs_pos:abs_pos+slen*2].decode('utf-16-le', errors='replace')

    REMOVE_ATTR_NAMES = {'requiredSplitTypes', 'splitTypes', 'extractNativeLibs'}
    REMOVE_META_VALUES = {
        'com.android.stamp.source', 'com.android.stamp.type',
        'com.android.vending.splits', 'com.android.vending.splits.required',
        'com.android.vending.derived.apk.id'
    }

    result = bytearray(data[:8])
    pos = 8
    skip_end = False
    changes = []

    while pos < len(data):
        if pos + 8 > len(data):
            break
        ct = struct.unpack('<H', data[pos:pos+2])[0]
        cs = struct.unpack('<I', data[pos+4:pos+8])[0]
        if cs == 0:
            break
        chunk = bytearray(data[pos:pos+cs])

        if ct == 0x0102:  # START_ELEMENT
            name_idx   = struct.unpack('<i', chunk[20:24])[0]
            el_name    = get_string(name_idx)
            attr_start = struct.unpack('<H', chunk[24:26])[0]
            attr_size_v= struct.unpack('<H', chunk[26:28])[0]
            attr_count = struct.unpack('<H', chunk[28:30])[0]
            abs_attr_off = 16 + attr_start

            attrs = []
            for i in range(attr_count):
                ap = abs_attr_off + i * attr_size_v
                attrs.append({
                    'name':  struct.unpack('<i', chunk[ap+4:ap+8])[0],
                    'raw':   struct.unpack('<i', chunk[ap+8:ap+12])[0],
                    'type':  chunk[ap+15],
                    'value': struct.unpack('<I', chunk[ap+16:ap+20])[0],
                    'ap':    ap
                })

            # ¿Es un <meta-data> a eliminar?
            if el_name == 'meta-data':
                for attr in attrs:
                    if get_string(attr['name']) == 'name':
                        v  = get_string(attr['raw']) if attr['raw'] >= 0 else ''
                        v2 = get_string(attr['value']) if attr['type'] == 3 else ''
                        val = v if v in REMOVE_META_VALUES else v2
                        if val in REMOVE_META_VALUES:
                            changes.append(f"  - Removed <meta-data name='{val}'/>")
                            skip_end = True
                            break
                if skip_end:
                    pos += cs
                    continue

            # Filtrar/modificar atributos
            kept = []
            for attr in attrs:
                aname = get_string(attr['name'])
                if aname in REMOVE_ATTR_NAMES:
                    changes.append(f"  - Removed attr '{aname}' from <{el_name}>")
                    continue
                if aname == 'minSdkVersion' and attr['value'] == 27:
                    struct.pack_into('<I', chunk, attr['ap']+16, 25)
                    changes.append(f"  - minSdkVersion: 27 → 25")
                kept.append(attr)

            if len(kept) < len(attrs):
                prefix    = bytes(chunk[:abs_attr_off])
                new_attrs = b''.join(bytes(chunk[a['ap']:a['ap']+attr_size_v]) for a in kept)
                new_chunk = bytearray(prefix + new_attrs)
                struct.pack_into('<H', new_chunk, 28, len(kept))
                struct.pack_into('<I', new_chunk, 4, len(new_chunk))
                result += new_chunk
            else:
                result += chunk

        elif ct == 0x0103:  # END_ELEMENT
            if skip_end:
                skip_end = False
                pos += cs
                continue
            result += chunk
        else:
            result += chunk

        pos += cs

    result = bytearray(result)
    struct.pack_into('<I', result, 4, len(result))
    return bytes(result), changes


# ─────────────────────────────────────────────
# FUSIÓN resources.arsc
# ─────────────────────────────────────────────

def read_utf8_sp(data, sp_abs):
    """Lee el string pool UTF-8 y devuelve lista de (text, raw_bytes)."""
    header = struct.unpack('<H', data[sp_abs+2:sp_abs+4])[0]
    count  = struct.unpack('<I', data[sp_abs+8:sp_abs+12])[0]
    flags  = struct.unpack('<I', data[sp_abs+16:sp_abs+20])[0]
    str_start = struct.unpack('<I', data[sp_abs+20:sp_abs+24])[0]
    utf8 = bool(flags & (1 << 8))
    strings = []
    for i in range(count):
        off = struct.unpack('<I', data[sp_abs+header+i*4:sp_abs+header+i*4+4])[0]
        p   = sp_abs + str_start + off
        if utf8:
            cb = data[p]; p += 2 if (cb & 0x80) else 1
            bb = data[p]; blen = ((bb & 0x7f) << 8) | data[p+1] if (bb & 0x80) else bb
            p += 2 if (bb & 0x80) else 1
            text = data[p:p+blen].decode('utf-8', 'replace')
        else:
            slen = struct.unpack('<H', data[p:p+2])[0]; p += 2
            text = data[p:p+slen*2].decode('utf-16-le', 'replace')
        strings.append(text)
    return strings

def merge_resources_arsc(base_arsc_data, xhdpi_arsc_data):
    """
    Fusiona el resources.arsc del split xhdpi con el del base.
    Agrega los Type/TypeSpec chunks del xhdpi al package del base,
    remapeando los índices del string pool global.
    """
    base  = bytearray(base_arsc_data)
    xhdpi = bytearray(xhdpi_arsc_data)

    # ── Leer string pool global del base ──
    gsp_abs     = 12
    gsp_header  = struct.unpack('<H', base[gsp_abs+2:gsp_abs+4])[0]
    gsp_old_size= struct.unpack('<I', base[gsp_abs+4:gsp_abs+8])[0]
    gsp_count   = struct.unpack('<I', base[gsp_abs+8:gsp_abs+12])[0]
    gsp_flags   = struct.unpack('<I', base[gsp_abs+16:gsp_abs+20])[0]
    gsp_str_start = struct.unpack('<I', base[gsp_abs+20:gsp_abs+24])[0]

    base_global_texts = read_utf8_sp(base, gsp_abs)

    old_offsets = [struct.unpack('<I', base[gsp_abs+gsp_header+i*4:gsp_abs+gsp_header+i*4+4])[0]
                   for i in range(gsp_count)]
    old_strings_data = bytes(base[gsp_abs + gsp_str_start : gsp_abs + gsp_old_size])

    # ── Leer string pool global del xhdpi ──
    xhdpi_gsp_abs = 12
    xhdpi_global_texts = read_utf8_sp(xhdpi, xhdpi_gsp_abs)

    # ── Construir mapping xhdpi_global_idx → base_global_idx ──
    xhdpi_to_base = {}
    new_strings_to_add = []
    current_off = len(old_strings_data)

    for xi, text in enumerate(xhdpi_global_texts):
        if text in base_global_texts:
            xhdpi_to_base[xi] = base_global_texts.index(text)
        else:
            xhdpi_to_base[xi] = gsp_count + len(new_strings_to_add)
            new_strings_to_add.append(text)

    # ── Construir nuevo string pool global ──
    new_strings_bytes = b''
    new_offsets = []
    for text in new_strings_to_add:
        new_offsets.append(current_off)
        encoded = text.encode('utf-8')
        blen = len(encoded)
        clen = len(text)
        cl = bytes([(clen >> 8) | 0x80, clen & 0xff]) if clen > 127 else bytes([clen])
        bl = bytes([(blen >> 8) | 0x80, blen & 0xff]) if blen > 127 else bytes([blen])
        s_bytes = cl + bl + encoded + b'\x00'
        new_strings_bytes += s_bytes
        current_off += len(s_bytes)

    new_gsp_count   = gsp_count + len(new_strings_to_add)
    new_str_start   = gsp_header + new_gsp_count * 4
    all_strings_data= old_strings_data + new_strings_bytes
    new_gsp_size    = new_str_start + len(all_strings_data)
    if new_gsp_size % 4 != 0:
        pad = 4 - new_gsp_size % 4
        all_strings_data += b'\x00' * pad
        new_gsp_size += pad

    new_gsp = bytearray()
    new_gsp += struct.pack('<H', 0x0001)
    new_gsp += struct.pack('<H', gsp_header)
    new_gsp += struct.pack('<I', new_gsp_size)
    new_gsp += struct.pack('<I', new_gsp_count)
    new_gsp += struct.pack('<I', 0)
    new_gsp += struct.pack('<I', gsp_flags)
    new_gsp += struct.pack('<I', new_str_start)
    new_gsp += struct.pack('<I', 0)
    for off in old_offsets + new_offsets:
        new_gsp += struct.pack('<I', off)
    new_gsp += all_strings_data

    # ── Extraer y remapar Type/TypeSpec chunks del xhdpi ──
    xsp_size   = struct.unpack('<I', xhdpi[16:20])[0]
    xpkg_off   = 12 + xsp_size
    xpkg_header= struct.unpack('<H', xhdpi[xpkg_off+2:xpkg_off+4])[0]
    xpkg_size  = struct.unpack('<I', xhdpi[xpkg_off+4:xpkg_off+8])[0]

    pos = xpkg_off + xpkg_header
    end = xpkg_off + xpkg_size
    xhdpi_chunks = bytearray()

    while pos < end:
        ct = struct.unpack('<H', xhdpi[pos:pos+2])[0]
        ch = struct.unpack('<H', xhdpi[pos+2:pos+4])[0]
        cs = struct.unpack('<I', xhdpi[pos+4:pos+8])[0]
        if cs == 0:
            break

        if ct == 0x0201:  # Type chunk — remapar string indices
            chunk        = bytearray(xhdpi[pos:pos+cs])
            entry_count  = struct.unpack('<I', chunk[12:16])[0]
            entries_start= struct.unpack('<I', chunk[16:20])[0]
            offsets_base_c = ch

            for i in range(entry_count):
                off = struct.unpack('<i', chunk[offsets_base_c+i*4:offsets_base_c+i*4+4])[0]
                if off == -1:
                    continue
                e_abs   = entries_start + off
                if e_abs + 8 > len(chunk):
                    continue
                e_size  = struct.unpack('<H', chunk[e_abs:e_abs+2])[0]
                e_flags = struct.unpack('<H', chunk[e_abs+2:e_abs+4])[0]

                if e_flags & 0x0001:  # FLAG_COMPLEX
                    val_count = struct.unpack('<I', chunk[e_abs+8:e_abs+12])[0]
                    for v in range(val_count):
                        vp = e_abs + 12 + v * 12
                        if vp + 12 > len(chunk):
                            break
                        if chunk[vp + 4 + 3] == 0x03:  # TYPE_STRING
                            old_idx = struct.unpack('<I', chunk[vp+8:vp+12])[0]
                            struct.pack_into('<I', chunk, vp+8, xhdpi_to_base.get(old_idx, old_idx))
                else:
                    vp = e_abs + e_size
                    if vp + 8 <= len(chunk) and chunk[vp + 3] == 0x03:
                        old_idx = struct.unpack('<I', chunk[vp+4:vp+8])[0]
                        struct.pack_into('<I', chunk, vp+4, xhdpi_to_base.get(old_idx, old_idx))

            xhdpi_chunks += chunk

        elif ct == 0x0202:  # TypeSpec
            xhdpi_chunks += xhdpi[pos:pos+cs]

        pos += cs

    # ── Ensamblar nuevo arsc ──
    base_sp_size  = struct.unpack('<I', base[16:20])[0]
    base_pkg_off  = 12 + base_sp_size
    base_pkg_size = struct.unpack('<I', base[base_pkg_off+4:base_pkg_off+8])[0]
    base_pkg_end  = base_pkg_off + base_pkg_size

    new_arsc = bytearray()
    new_arsc += base[:12]
    new_arsc += new_gsp
    pkg_start = len(new_arsc)
    new_arsc += base[base_pkg_off:base_pkg_end]
    new_arsc += xhdpi_chunks
    if base_pkg_end < len(base):
        new_arsc += base[base_pkg_end:]

    struct.pack_into('<I', new_arsc, pkg_start + 4, base_pkg_size + len(xhdpi_chunks))
    struct.pack_into('<I', new_arsc, 4, len(new_arsc))

    return bytes(new_arsc)


# ─────────────────────────────────────────────
# FIRMA
# ─────────────────────────────────────────────

def find_apksigner():
    """Busca apksigner en el PATH y ubicaciones comunes (Windows, macOS, Linux)."""
    is_windows = sys.platform == 'win32'
    exe = 'apksigner.bat' if is_windows else 'apksigner'

    # 1. PATH del sistema
    found = shutil.which(exe)
    if found:
        return found

    home = os.path.expanduser('~')

    # 2. Ubicaciones de Android Studio / SDK
    sdk_roots = []

    if is_windows:
        # Android Studio instala el SDK aquí por defecto en Windows
        sdk_roots += [
            os.path.join(home, 'AppData', 'Local', 'Android', 'Sdk'),
            os.path.join(home, 'Android', 'Sdk'),
            r'C:\Android\Sdk',
            r'C:\Program Files\Android\Android Studio\sdk',
        ]
        # También buscar via variable de entorno ANDROID_HOME / ANDROID_SDK_ROOT
        for env_var in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
            val = os.environ.get(env_var)
            if val:
                sdk_roots.insert(0, val)
    elif sys.platform == 'darwin':
        sdk_roots += [
            os.path.join(home, 'Library', 'Android', 'sdk'),
            os.path.join(home, 'Android', 'Sdk'),
        ]
    else:
        sdk_roots += [
            os.path.join(home, 'Android', 'Sdk'),
            '/usr/lib/android-sdk',
            '/opt/android-sdk',
        ]

    for sdk_root in sdk_roots:
        bt_dir = os.path.join(sdk_root, 'build-tools')
        pattern = os.path.join(bt_dir, '*', exe)
        matches = sorted(glob.glob(pattern), reverse=True)
        if matches:
            return matches[0]

    return None

def find_keytool():
    """Busca keytool en el PATH y en ubicaciones de JDK comunes en Windows."""
    found = shutil.which('keytool')
    if found:
        return found

    if sys.platform == 'win32':
        # JDK incluido en Android Studio (Windows)
        home = os.path.expanduser('~')
        patterns = [
            r'C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe',
            r'C:\Program Files\Android\Android Studio\jre\bin\keytool.exe',
            os.path.join(home, 'AppData', 'Local', 'Programs', 'Android Studio', 'jbr', 'bin', 'keytool.exe'),
            r'C:\Program Files\Java\jdk*\bin\keytool.exe',
            r'C:\Program Files\Eclipse Adoptium\jdk*\bin\keytool.exe',
        ]
        for pattern in patterns:
            matches = sorted(glob.glob(pattern), reverse=True)
            if matches:
                return matches[0]

    return None

def sign_apk(unsigned_apk, signed_apk, keystore_path, keystore_pass, key_alias, key_pass):
    apksigner = find_apksigner()
    if not apksigner:
        print("  ✗ apksigner no encontrado.")
        print("    Opciones:")
        print("    1. Abrir Android Studio → SDK Manager → SDK Tools → instalar 'Android SDK Build-Tools'")
        print("    2. O agregar al PATH: C:\\Users\\TU_USUARIO\\AppData\\Local\\Android\\Sdk\\build-tools\\<version>")
        return False

    print(f"  apksigner: {apksigner}")

    # apksigner.bat en Windows necesita ser invocado con cmd /c
    if sys.platform == 'win32' and apksigner.endswith('.bat'):
        cmd = ['cmd', '/c', apksigner]
    else:
        cmd = [apksigner]

    cmd += [
        'sign',
        '--ks', keystore_path,
        '--ks-pass', f'pass:{keystore_pass}',
        '--key-pass', f'pass:{key_pass}',
        '--ks-key-alias', key_alias,
        '--v1-signing-enabled', 'true',
        '--v2-signing-enabled', 'true',
        '--v3-signing-enabled', 'false',
        '--min-sdk-version', '25',
        '--out', signed_apk,
        unsigned_apk,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ✗ Error al firmar:\n{result.stderr}")
        return False
    return True

def ensure_keystore(keystore_path):
    """Crea un debug keystore si no existe."""
    if os.path.exists(keystore_path):
        return True
    keytool = find_keytool()
    if not keytool:
        print("  ✗ keytool no encontrado.")
        print("    En Android Studio: File → Project Structure → SDK Location → JDK location")
        print("    Agregar <jdk_path>\\bin al PATH")
        return False
    cmd = [
        keytool, '-genkeypair', '-v',
        '-keystore', keystore_path,
        '-alias', 'androiddebugkey',
        '-keyalg', 'RSA', '-keysize', '2048',
        '-validity', '10000',
        '-storepass', 'android',
        '-keypass', 'android',
        '-dname', 'CN=Android Debug,O=Android,C=US'
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


# ─────────────────────────────────────────────
# PROCESO PRINCIPAL
# ─────────────────────────────────────────────

def convert(apkm_path):
    apkm_path = os.path.abspath(apkm_path)
    work_dir  = tempfile.mkdtemp(prefix='flow_convert_')

    try:
        print(f"\n{'='*60}")
        print(f"  FlowATV APKM → APK Android 8.0 Converter")
        print(f"{'='*60}")
        print(f"  Input:  {apkm_path}")

        # ── 1. Extraer APKM ──
        print("\n[1/7] Extrayendo APKM...")
        apkm_dir = os.path.join(work_dir, 'apkm')
        os.makedirs(apkm_dir)
        with zipfile.ZipFile(apkm_path, 'r') as z:
            z.extractall(apkm_dir)

        base_apk = os.path.join(apkm_dir, 'base.apk')
        if not os.path.exists(base_apk):
            print("  ✗ base.apk no encontrado en el APKM")
            return False

        # Leer versión del APK
        try:
            result = subprocess.run(['aapt', 'dump', 'badging', base_apk],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'versionName' in line:
                    version = line.split("versionName='")[1].split("'")[0]
                    break
            else:
                version = 'unknown'
        except Exception:
            version = 'unknown'
        print(f"  Versión detectada: {version}")

        # ── 2. Extraer base.apk y splits ──
        print("\n[2/7] Extrayendo base.apk y splits de arquitectura...")
        base_dir = os.path.join(work_dir, 'base')
        os.makedirs(base_dir)
        with zipfile.ZipFile(base_apk, 'r') as z:
            z.extractall(base_dir)

        lib_dirs = {}
        for abi, split_name in [('arm64-v8a', 'split_config.arm64_v8a.apk'),
                                  ('armeabi-v7a', 'split_config.armeabi_v7a.apk')]:
            split_path = os.path.join(apkm_dir, split_name)
            if os.path.exists(split_path):
                out_dir = os.path.join(work_dir, f'split_{abi}')
                os.makedirs(out_dir)
                with zipfile.ZipFile(split_path, 'r') as z:
                    z.extractall(out_dir)
                lib_dir = os.path.join(out_dir, 'lib', abi)
                if os.path.exists(lib_dir):
                    lib_dirs[abi] = lib_dir
                    print(f"  Libs {abi}: {len(os.listdir(lib_dir))} archivos")

        xhdpi_split_path = os.path.join(apkm_dir, 'split_config.xhdpi.apk')
        has_xhdpi = os.path.exists(xhdpi_split_path)
        if has_xhdpi:
            print(f"  Split xhdpi: encontrado")

        # ── 3. Parchear DEX ──
        print("\n[3/7] Parcheando DEX (038 → 037)...")
        dex_dir = base_dir
        dex_count = 0
        for fname in sorted(os.listdir(dex_dir)):
            if not fname.endswith('.dex'):
                continue
            path = os.path.join(dex_dir, fname)
            with open(path, 'rb') as f:
                original = f.read()
            ver = original[4:7].decode('ascii', errors='replace')
            patched = patch_dex(original)
            with open(path, 'wb') as f:
                f.write(patched)
            new_ver = patched[4:7].decode('ascii', errors='replace')
            print(f"  {fname}: {ver} → {new_ver}")
            dex_count += 1
        print(f"  Total: {dex_count} DEX parchados")

        # ── 4. Parchear AndroidManifest ──
        print("\n[4/7] Parcheando AndroidManifest.xml...")
        manifest_path = os.path.join(base_dir, 'AndroidManifest.xml')
        if not os.path.exists(manifest_path):
            # Leer del base.apk directamente
            with zipfile.ZipFile(base_apk, 'r') as z:
                manifest_data = z.read('AndroidManifest.xml')
        else:
            with open(manifest_path, 'rb') as f:
                manifest_data = f.read()

        with zipfile.ZipFile(base_apk, 'r') as z:
            manifest_data = z.read('AndroidManifest.xml')

        patched_manifest, changes = patch_manifest(manifest_data)
        for c in changes:
            print(c)

        # ── 5. Fusionar resources.arsc ──
        print("\n[5/7] Fusionando resources.arsc con split xhdpi...")
        with zipfile.ZipFile(base_apk, 'r') as z:
            base_arsc_data = z.read('resources.arsc')

        if has_xhdpi:
            with zipfile.ZipFile(xhdpi_split_path, 'r') as z:
                xhdpi_arsc_data = z.read('resources.arsc')
            merged_arsc = merge_resources_arsc(base_arsc_data, xhdpi_arsc_data)
            print(f"  resources.arsc: {len(base_arsc_data)} → {len(merged_arsc)} bytes")
        else:
            merged_arsc = base_arsc_data
            print("  Split xhdpi no encontrado, usando arsc original")

        # ── 6. Ensamblar APK ──
        print("\n[6/7] Ensamblando APK...")
        unsigned_apk = os.path.join(work_dir, 'unsigned.apk')

        xhdpi_res = {}
        if has_xhdpi:
            with zipfile.ZipFile(xhdpi_split_path, 'r') as z:
                for item in z.infolist():
                    if item.filename.startswith('res/'):
                        xhdpi_res[item.filename] = (z.read(item.filename), item.compress_type)

        split_libs = {}
        for abi, lib_dir in lib_dirs.items():
            for lib in os.listdir(lib_dir):
                with open(os.path.join(lib_dir, lib), 'rb') as f:
                    split_libs[f'lib/{abi}/{lib}'] = f.read()

        SKIP_META = {'.RSA', '.SF', 'MANIFEST.MF'}
        ALIGN_LIB = 4096
        entries = []
        added   = set()

        out_f = open(unsigned_apk, 'wb')

        with zipfile.ZipFile(base_apk, 'r') as zin:
            for item in zin.infolist():
                n = item.filename
                if any(n.endswith(s) for s in SKIP_META): continue
                if n.endswith('.dex'): continue
                if n == 'AndroidManifest.xml': continue
                if n == 'resources.arsc': continue
                if n.startswith('lib/'): continue
                if n in added: continue
                data  = zin.read(n)
                store = (item.compress_type == 0)
                write_zip_entry(out_f, entries, n, data, store=store)
                added.add(n)

        # resources.arsc mergeado (STORED)
        write_zip_entry(out_f, entries, 'resources.arsc', merged_arsc, store=True)
        added.add('resources.arsc')

        # Recursos del split xhdpi
        for name, (data, orig_compress) in xhdpi_res.items():
            if name in added: continue
            write_zip_entry(out_f, entries, name, data, store=(orig_compress == 0))
            added.add(name)

        # AndroidManifest parchado
        write_zip_entry(out_f, entries, 'AndroidManifest.xml', patched_manifest, store=False)

        # DEX parchados
        for fname in sorted(os.listdir(dex_dir)):
            if not fname.endswith('.dex'): continue
            with open(os.path.join(dex_dir, fname), 'rb') as f:
                write_zip_entry(out_f, entries, fname, f.read(), store=False)

        # Libs nativas STORED + 4096-aligned
        for key in sorted(split_libs.keys()):
            write_zip_entry(out_f, entries, key, split_libs[key], store=True, align=ALIGN_LIB)

        write_zip_central_directory(out_f, entries)
        out_f.close()

        size_mb = os.path.getsize(unsigned_apk) / 1024 / 1024
        print(f"  APK ensamblado: {len(entries)} entradas, {size_mb:.1f} MB")

        # ── 7. Firmar ──
        print("\n[7/7] Firmando APK...")
        keystore_path = os.path.join(os.path.dirname(apkm_path), 'debug.keystore')
        if not ensure_keystore(keystore_path):
            keystore_path = os.path.join(os.path.expanduser('~'), '.android', 'debug.keystore')
            ensure_keystore(keystore_path)

        out_name = f"FlowATV_{version}_Android8.apk"
        out_apk  = os.path.join(os.path.dirname(apkm_path), out_name)

        if sign_apk(unsigned_apk, out_apk, keystore_path, 'android', 'androiddebugkey', 'android'):
            size_mb = os.path.getsize(out_apk) / 1024 / 1024
            print(f"\n{'='*60}")
            print(f"  ✓ ÉXITO")
            print(f"  Salida: {out_apk}")
            print(f"  Tamaño: {size_mb:.1f} MB")
            print(f"{'='*60}\n")
            return True
        else:
            # Si falla la firma, al menos guardar el sin firmar
            shutil.copy(unsigned_apk, out_apk.replace('.apk', '_unsigned.apk'))
            print(f"  APK sin firmar guardado (instalar manualmente con apksigner)")
            return False

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ─────────────────────────────────────────────
# ENTRADA
# ─────────────────────────────────────────────

if __name__ == '__main__':
    # Buscar el APKM a convertir
    if len(sys.argv) > 1:
        apkm = sys.argv[1]
    else:
        # Buscar automáticamente en la misma carpeta que el script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        apkms = glob.glob(os.path.join(script_dir, '*.apkm'))
        if not apkms:
            print("ERROR: No se encontró ningún archivo .apkm en la carpeta.")
            print("Uso: python3 convert_flow_apkm.py <archivo.apkm>")
            sys.exit(1)
        if len(apkms) > 1:
            print("Múltiples .apkm encontrados. Seleccioná uno:")
            for i, a in enumerate(apkms):
                print(f"  [{i+1}] {os.path.basename(a)}")
            choice = input("Número: ").strip()
            apkm = apkms[int(choice) - 1]
        else:
            apkm = apkms[0]
            print(f"APKM encontrado: {os.path.basename(apkm)}")

    if not os.path.exists(apkm):
        print(f"ERROR: Archivo no encontrado: {apkm}")
        sys.exit(1)

    success = convert(apkm)
    sys.exit(0 if success else 1)
