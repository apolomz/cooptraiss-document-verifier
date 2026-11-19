# COOPTRAISS | Verificador documental

**Prototipo académico para la generación y verificación de firmas digitales criptográficas en documentos, como apoyo a la auditoría de seguridad de la información del proceso de ahorro de COOPTRAISS.**

---

## 1. Contexto Académico

Este aplicativo ha sido desarrollado en el marco de la asignatura de **Ciberseguridad** de la **Universidad del Valle** (Cali, Colombia).

Forma parte de una auditoría de integridad de seguridad de la información centrada exclusivamente en el **proceso de ahorro** de **COOPTRAISS** (Cooperativa de los Trabajadores del ISS). El alcance no abarca el proceso de crédito ni otros servicios financieros.

Durante el análisis de riesgos y evaluación de controles de los activos de información del proceso de ahorro, se identificó la vulnerabilidad asociada a la potencial alteración, falsificación o repudio de documentos sensibles (certificados de ahorro CDAT, constancias de saldos y solicitudes de apertura/cancelación). En respuesta, se diseñó este prototipo independiente para evidenciar de manera práctica cómo los mecanismos criptográficos de clave pública y funciones resumen garantizan la **integridad** y la **autenticidad de origen** documental.

> **Aviso:** Este aplicativo es un prototipo con fines académicos y demostrativos. **No constituye un producto ni canal oficial de COOPTRAISS**, ni representa una implementación respaldada por dicha entidad.

---

## 2. Objetivo del Aplicativo

Demostrar la aplicación práctica de primitivas criptográficas robustas (RSA-PSS y SHA-256) en el aseguramiento del ciclo de vida documental del proceso de ahorro, permitiendo:

1. Calcular la huella digital criptográfica (hash) inalterable de un documento original.
2. Firmar digitalmente los bytes originales del documento mediante criptografía asimétrica.
3. Empaquetar y exportar de forma segura los artefactos necesarios para la verificación independiente.
4. Detectar de manera inmediata cualquier modificación no autorizada en el contenido del documento o en su firma.
5. Contrastar los mecanismos criptográficos frente a las necesidades de una Infraestructura de Clave Pública (PKI).

---

## 3. Funcionalidades

El aplicativo cuenta con dos módulos principales accesibles desde una interfaz web:

### Módulo A: Firmar Documento
- **Soporte multiformato:** Admite archivos PDF, DOCX, TXT, PNG, JPG, entre otros formatos comunes (hasta 20 MB).
- **Procesamiento en memoria:** Los archivos se procesan directamente en memoria volátil sin almacenarse en el disco del servidor.
- **Cálculo de Hash SHA-256:** Obtiene la huella criptográfica de 256 bits (64 caracteres hexadecimales) de los bytes originales.
- **Generación de Claves RSA:** Genera pares de claves RSA efímeras de 3072 bits.
- **Firma Digital RSA-PSS:** Genera la firma digital empleando el esquema probabilístico PSS (Probabilistic Signature Scheme) con máscara MGF1 y SHA-256.
- **Exportación en Paquete ZIP Seguro:** Descarga de un paquete que integra:
  - `documento_original.bin`: Contenido binario exacto del archivo firmado.
  - `firma.sig`: Firma digital binaria.
  - `clave_publica.pem`: Clave pública en formato estándar PEM (SubjectPublicKeyInfo).
  - `manifest.json`: Metadatos descriptivos del proceso de firma y hash de referencia.
- **Protección de clave privada:** La clave privada nunca se almacena en disco, no se incluye en el archivo ZIP y se destruye de la memoria una vez completada la firma.

### Módulo B: Verificar Documento
Ofrece dos modalidades de verificación:
- **Modalidad 1: Paquete ZIP completo (Recomendada):** El usuario carga el archivo ZIP exportado. El sistema valida en memoria la integridad del archivo, inspecciona el manifiesto, recalcula el hash SHA-256 del documento y verifica la firma contra la clave pública adjunta.
- **Modalidad 2: Archivos individuales:** Permite cargar por separado el documento, el archivo de firma (`.sig`) y la clave pública (`.pem`), verificando la correspondencia criptográfica.

### Resultados de Verificación
El sistema clasifica el resultado en tres estados categóricos:
1. **Firma válida:** Documento íntegro, coincidencia exacta con el manifiesto y firma verificada matemáticamente.
2. **Firma inválida:** Discrepancia en el hash SHA-256, alteración en el documento, firma corrupta o clave pública no correspondiente.
3. **Error de entrada o paquete:** Archivos corruptos, formatos JSON inválidos en el manifiesto, claves no válidas o anomalías estructurales en el ZIP.

---

## 4. Tecnologías y Algoritmos Criptográficos

| Componente | Tecnología / Estándar | Justificación Técnica |
| :--- | :--- | :--- |
| **Lenguaje base** | Python 3.13.3 |
| **Interfaz web** | Streamlit | Framework para herramientas analíticas y de auditoría. |
| **Motor criptográfico** | Cryptography (hazmat) | Estándar de la industria para operaciones criptográficas de bajo nivel. |
| **Pruebas unitarias** | Pytest | Automatización de pruebas unitarias y de integración. |
| **Función resumen** | SHA-256 | Resistencia comprobada a colisiones y preimagen (FIPS 180-4). |
| **Criptografía asimétrica** | RSA de 3072 bits | Nivel de seguridad equivalente a 128 bits simétricos (recomendación NIST SP 800-57 para protección posterior a 2030). |
| **Esquema de firma** | RSA-PSS (PKCS#1 v2.1) | Esquema probabilístico con demostración formal de seguridad superior a PKCS#1 v1.5, con salteo criptográfico dinámico. |
| **Serialización de clave** | PEM (SubjectPublicKeyInfo) | Formato estándar de codificación de claves públicas (RFC 5280). |

---

## 5. Arquitectura y Estructura del Proyecto

```
cooptraiss-auditoria/
│
├── app.py                      # Interfaz web Streamlit y orquestación de flujos
├── requirements.txt            # Dependencias estrictas del proyecto
├── README.md                   # Documentación técnica completa
├── .gitignore                  
│
├── .streamlit/
│   └── config.toml             # Configuración de tema corporativo y parámetros del servidor
│
├── crypto/
│   ├── __init__.py             
│   ├── keys.py                 # Generación, serialización y carga de claves RSA
│   ├── signer.py               # Cálculo de SHA-256 y firma digital RSA-PSS
│   └── verifier.py             # Verificación matemática de firmas RSA-PSS
│
├── utils/
│   ├── __init__.py          
│   └── documents.py            # Gestión en memoria de ZIP, sanitización y manifiestos
│
├── examples/
│   ├── .gitkeep
│   └── certificado_cdat_demo.txt # Documento ficticio para pruebas de auditoría
│
└── tests/
    ├── __init__.py
    └── test_signature.py       # Suite completa de 19 pruebas automatizadas
```

---


## 7. Instalación 

Abra una consola en la raíz del proyecto (`cooptraiss-auditoria`):

```powershell
# 1. Crear entorno virtual con Python 3.13
py -3.13 -m venv .venv

# 2. Activar el entorno virtual
.venv\Scripts\Activate.ps1

# 3. Instalar las dependencias
pip install -r requirements.txt
```

---

## 8. Ejecución Local

Con el entorno virtual activado, ejecute:

```powershell
streamlit run app.py
```

La aplicación abrirá automáticamente una pestaña en su navegador (habitualmente en `http://localhost:8501`).

---

## 9. Ejecución de Pruebas Automatizadas

El proyecto incluye 19 pruebas unitarias y de integración que validan exhaustivamente la suite criptográfica y la seguridad de los archivos:

```powershell
pytest -v
```

### Cobertura de las pruebas obligatorias:
1. `test_valid_signature`: Verificación matemática exitosa de firmas válidas.
2. `test_modified_document_fails`: Detección inmediata de alteración (1 carácter) en el documento.
3. `test_wrong_public_key_fails`: Rechazo de firmas evaluadas con claves públicas no correspondientes.
4. `test_public_key_serialization`: Exportación PEM y reconstrucción fidedigna de claves RSA.
5. `test_sha256_length`: Verificación del formato y longitud estricta de 64 caracteres de SHA-256.
6. `test_empty_document_fails`: Rechazo controlado de documentos vacíos (0 bytes).
7. `test_zip_package_creation`: Construcción en memoria del ZIP con los cuatro elementos requeridos.
8. `test_zip_package_reading`: Deserialización e inspección segura de paquetes ZIP.
9. `test_verify_package_valid`: Flujo completo de verificación positiva de paquetes íntegros.
10. `test_verify_package_modified_document`: Detección de documentos manipulados dentro del paquete ZIP.
11. `test_corrupted_signature`: Rechazo de firmas binarias truncadas o alteradas.
12. `test_invalid_public_key`: Manejo seguro de claves públicas PEM dañadas o no-RSA.
13. `test_corrupted_manifest`: Validación estricta del esquema JSON y campos obligatorios del manifiesto.
14. `test_invalid_zip_file`: Manejo defensivo de archivos no válidos o corruptos.
15. `test_zip_duplicate_or_unexpected_entries`: Mitigación de ataques Zip Slip, archivos extras y nombres duplicados.
16. `test_document_size_validation`: Control de tamaño de archivos (rechazo de vacíos y mayores a 20 MB).
17. `test_verify_individual_files_valid`: Verificación exitosa en modalidad de archivos separados.
18. `test_verify_individual_files_tampered`: Detección de manipulación en archivos individuales.
19. `test_filename_sanitization`: Sanitización de nombres de archivo y mitigación de path traversal.

---

## 10. Guía Paso a Paso para la Demostración

Para realizar una demostración académica:

### Paso 1: Firma de un documento de ahorro ficticio
1. Inicie la aplicación con `streamlit run app.py`.
2. En la pestaña **Firmar documento**, haga clic en **Browse files** y seleccione el archivo de demostración provisto en:
   `examples/certificado_cdat_demo.txt`.
3. Observe la información preliminar: nombre del archivo, formato TXT y tamaño.
4. Presione el botón **Generar firma criptográfica**.
5. Examine los datos técnicos generados:
   - Hash SHA-256 calculado.
   - Algoritmo de firma RSA-PSS con clave de 3072 bits.
6. Haga clic en **Descargar paquete de verificación (ZIP)** y guarde el archivo descargado.

### Paso 2: Verificación exitosa de integridad
1. Diríjase a la pestaña **Verificar documento**.
2. Con la modalidad **Paquete ZIP completo** seleccionada, cargue el archivo ZIP recién descargado.
3. Presione el botón **Verificar firma del paquete**.
4. Se desplegará el panel verde con el mensaje:
   > *"Firma criptográfica válida. El documento corresponde a la firma proporcionada y no se detectaron alteraciones respecto al contenido firmado."*
5. Se apreciará la coincidencia exacta entre el hash calculado y el hash registrado en el manifiesto.

### Paso 3: Demostración de detección de alteración (Falsificación)
1. Extraiga temporalmente el archivo `documento_original.bin` del ZIP en un directorio de prueba.
2. Ábralo con el Bloc de Notas y modifique un dato sensible, por ejemplo cambiando el monto de `$ 5.000.000 COP` a `$ 50.000.000 COP`.
3. Vuelva a comprimir los cuatro archivos en un nuevo ZIP (o reemplace el archivo modificado dentro del ZIP).
4. Cargue el ZIP alterado en el verificador y presione **Verificar firma del paquete**.
5. El sistema detectará automáticamente la discrepancia y desplegará el panel rojo de alerta:
   > *"Firma criptográfica inválida. El hash SHA-256 del documento no coincide con el registrado en el manifiesto. La firma criptográfica RSA-PSS no corresponde al contenido del documento o a la clave pública."*

---

## 11. Estructura y Contenido del Paquete ZIP

El paquete generado se compone de cuatro archivos estrictamente definidos:

```
paquete_firma_<nombre>.zip
│
├── documento_original.bin   # Copia exacta del documento firmado en formato binario original.
├── firma.sig                # Firma digital binaria generada mediante RSA-PSS (384 bytes para RSA-3072).
├── clave_publica.pem        # Clave pública en formato PEM SubjectPublicKeyInfo codificada en Base64.
└── manifest.json            # Metadatos del proceso en formato JSON UTF-8.
```

### Ejemplo de `manifest.json`:
```json
{
  "version": "1.0",
  "original_filename": "certificado_cdat_demo.txt",
  "file_size_bytes": 1642,
  "hash_algorithm": "SHA-256",
  "signature_algorithm": "RSA-PSS con SHA-256",
  "key_size_bits": 3072,
  "document_sha256": "4a5c...7e9b",
  "created_at": "2026-11-19T11:20:00Z",
  "application": "COOPTRAISS | Verificador documental",
  "academic_context": "Auditoría de seguridad de la información - Proceso de Ahorro COOPTRAISS (Universidad del Valle)",
  "academic_disclaimer": "Prototipo académico independiente. Sin validez legal o contractual. No constituye un canal oficial de COOPTRAISS."
}
```

---

## 12. Consideraciones de Seguridad y Buenas Prácticas

1. **Aislamiento en memoria (Zero-Disk Storage):** Tanto la firma como la verificación operan en búferes de memoria (`io.BytesIO`). Ningún documento o firma de los usuarios se almacena en el disco del servidor.
2. **Protección de la Clave Privada:** La clave privada generada para la firma se instancia únicamente en memoria volátil y se elimina de forma inmediata una vez calculada la firma. Nunca se expone al cliente ni se incluye en el ZIP.
3. **Defensa contra Zip Slip:** El descompresor en memoria valida cada nombre de archivo impidiendo rutas que contengan retrocesos de directorio (`..`), barras oblicuas (`/`) o barras invertidas (`\`).
4. **Defensa contra Zip Bombs:** Se restringe el tamaño máximo por documento a 20 MB y el tamaño total acumulado descomprimido a 50 MB, previniendo ataques de denegación de servicio por agotamiento de memoria.
5. **Prevención de colisiones por nombres duplicados:** Se rechazan paquetes ZIP que contengan archivos con nombres repetidos.
6. **Manejo seguro de excepciones:** Todos los errores de parsing, firmas inválidas y claves truncadas se capturan controladamente para no exponer trazas de depuración (tracebacks) al usuario final.
7. **Ausencia de ejecución dinámica:** El aplicativo no hace uso de `eval()`, `exec()` ni llamadas a shells del sistema operativo.

---

## 13. Limitaciones del Prototipo y Alcance Legal

- **Firma Digital vs. Firma Certificada:** En la legislación colombiana (Ley 527 de 1999 y Decreto 2364 de 2012), la validez jurídica probatoria plena de una firma digital requiere estar asociada a un certificado digital emitido por una **Entidad de Certificación Digital (ECD) abierta o cerrada debidamente acreditada** por el ONAC. Este prototipo utiliza claves asimétricas autogeneradas sin cadena de certificación X.509.
- **Identidad de los participantes:** La validez matemática de una firma demuestra que el documento no ha sido alterado desde su emisión y que coincide con la clave pública evaluada; no obstante, **no prueba por sí misma la identidad real de una persona física o jurídica**, a menos que la clave pública sea vinculada previamente a través de un canal seguro y confiable.
- **Sellado de Tiempo (Timestamping):** Las marcas temporales incluidas en el manifiesto son referenciales del sistema local y no provienen de una Autoridad de Sellado de Tiempo (TSA) con sincronización horaria certificada.
- **Propósito didáctico:** El aplicativo está diseñado como herramienta ilustrativa de controles de seguridad lógica para apoyar los hallazgos y recomendaciones de la auditoría de seguridad del proceso de ahorro de COOPTRAISS.
