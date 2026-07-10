package com.firmar.demo.service;

import ec.gob.firmadigital.libreria.sign.DigestAlgorithm;
import ec.gob.firmadigital.libreria.sign.PrivateKeySigner;
import ec.gob.firmadigital.libreria.sign.RubricaSigner;
import ec.gob.firmadigital.libreria.sign.pdf.BaseSigner;
import ec.gob.firmadigital.libreria.sign.pdf.PadesBasic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@Service
public class FirmaDigitalService {
    
    private static final Logger logger = LoggerFactory.getLogger(FirmaDigitalService.class);
    
    public FirmaResponse firmarPdf(byte[] pdfBytes, byte[] certificadoBytes, 
                                   String password, String nombreArchivo) 
            throws Exception {
        return firmarPdf(pdfBytes, certificadoBytes, password, nombreArchivo,
                "QR", "1", 50, 50, 150, 150, 
                "Firma digital de documento", "Ecuador");
    }
    
    public FirmaResponse firmarPdf(byte[] pdfBytes, byte[] certificadoBytes, 
                                   String password, String nombreArchivo,
                                   String typeSignature,
                                   String signingPage,
                                   Integer posX, Integer posY,
                                   Integer width, Integer height,
                                   String signingReason,
                                   String signingLocation) 
            throws Exception {
        
        logger.info("Iniciando proceso de firma digital");
        logger.info("Tipo de firma: {}, Página: {}, Posición: ({}, {}), Tamaño: {}x{}", 
                typeSignature, signingPage, posX, posY, width, height);
        
        try {
            KeyAndCertificateChain privateKeyAndCertificateChain = 
                    extraerClaveYCertificado(certificadoBytes, password);
            
            PrivateKey privateKey = privateKeyAndCertificateChain.getPrivateKey();
            Certificate[] chain = privateKeyAndCertificateChain.getCertificateChain();
            
            String nombreFirmante = obtenerNombreSujeto(chain[0]);
            
            byte[] pdfFirmado = firmarPdfConPades(
                    pdfBytes, 
                    privateKey, 
                    chain, 
                    nombreFirmante,
                    typeSignature,
                    signingPage,
                    posX, posY,
                    width, height,
                    signingReason,
                    signingLocation
            );
            
            logger.info("Firma digital completada exitosamente");
            
            return new FirmaResponse(
                    pdfFirmado,
                    nombreFirmante,
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date()),
                    true,
                    "Documento firmado exitosamente"
            );
            
        } catch (Exception e) {
            logger.error("Error al firmar el documento: {}", e.getMessage(), e);
            throw new Exception("Error al firmar el documento: " + e.getMessage(), e);
        }
    }

    public FirmaResponse firmarPdfMultiple(byte[] pdfBytes, byte[] certificadoBytes,
                                           String password, String nombreArchivo,
                                           String typeSignature,
                                           String signingPage,
                                           Integer posX, Integer posY,
                                           Integer width, Integer height,
                                           String signingReason,
                                           String signingLocation,
                                           String additionalPositionsJson) throws Exception {

        logger.info("Iniciando proceso de firma digital múltiple");
        logger.info("Posición principal: Página: {}, Posición: ({}, {}), Tamaño: {}x{}",
                signingPage, posX, posY, width, height);

        try {
            KeyAndCertificateChain privateKeyAndCertificateChain =
                    extraerClaveYCertificado(certificadoBytes, password);

            PrivateKey privateKey = privateKeyAndCertificateChain.getPrivateKey();
            Certificate[] chain = privateKeyAndCertificateChain.getCertificateChain();

            String nombreFirmante = obtenerNombreSujeto(chain[0]);

            // Crear lista de posiciones
            List<SignaturePosition> positions = new ArrayList<>();
            positions.add(new SignaturePosition(signingPage, posX, posY, width, height));

            // Procesar posiciones adicionales
            if (additionalPositionsJson != null && !additionalPositionsJson.isEmpty()) {
                try {
                    com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                    SignaturePosition[] additional = mapper.readValue(additionalPositionsJson, SignaturePosition[].class);
                    for (SignaturePosition pos : additional) {
                        positions.add(pos);
                    }
                    logger.info("Se agregaron {} posiciones adicionales de firma", additional.length);
                } catch (Exception e) {
                    logger.warn("Error al parsear posiciones adicionales: {}", e.getMessage());
                }
            }

            logger.info("Total de firmas a aplicar: {}", positions.size());

            // Firmar PDF con todas las posiciones
            byte[] pdfFirmado = pdfBytes;
            for (int i = 0; i < positions.size(); i++) {
                SignaturePosition pos = positions.get(i);
                logger.info("Aplicando firma {} de {} - Página: {}, Posición: ({}, {}), Tamaño: {}x{}",
                        (i + 1), positions.size(), pos.page, pos.x, pos.y, pos.width, pos.height);

                pdfFirmado = firmarPdfConPades(
                        pdfFirmado,
                        privateKey,
                        chain,
                        nombreFirmante,
                        typeSignature,
                        pos.page,
                        pos.x, pos.y,
                        pos.width, pos.height,
                        signingReason,
                        signingLocation
                );
            }

            logger.info("Firma digital múltiple completada exitosamente");

            return new FirmaResponse(
                    pdfFirmado,
                    nombreFirmante,
                    new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date()),
                    true,
                    "Documento firmado exitosamente con " + positions.size() + " firma(s)"
            );

        } catch (Exception e) {
            logger.error("Error al firmar el documento: {}", e.getMessage(), e);
            throw new Exception("Error al firmar el documento: " + e.getMessage(), e);
        }
    }

    private static class SignaturePosition {
        public String page;
        public Integer x;
        public Integer y;
        public Integer width;
        public Integer height;

        public SignaturePosition() {}

        public SignaturePosition(String page, Integer x, Integer y, Integer width, Integer height) {
            this.page = page;
            this.x = x;
            this.y = y;
            this.width = width;
            this.height = height;
        }
    }
    
    private static class KeyAndCertificateChain {
        private final String alias;
        private final PrivateKey privateKey;
        private final Certificate[] certificateChain;

        public KeyAndCertificateChain(String alias, PrivateKey privateKey, Certificate[] certificateChain) {
            this.alias = alias;
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }

        public String getAlias() {
            return alias;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public Certificate[] getCertificateChain() {
            return certificateChain;
        }
    }

    private KeyAndCertificateChain extraerClaveYCertificado(byte[] certificadoBytes, String password)
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(certificadoBytes), password.toCharArray());

        String alias = keyStore.aliases().nextElement();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);

        return new KeyAndCertificateChain(alias, privateKey, certificateChain);
    }
    
    private String obtenerNombreSujeto(Certificate certificado) {
        try {
            java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) certificado;
            String dn = x509.getSubjectX500Principal().getName();
            
            String[] parts = dn.split(",");
            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("CN=")) {
                    return part.substring(3);
                }
            }
            return dn;
        } catch (Exception e) {
            logger.warn("No se pudo obtener el nombre del firmante, usando valor por defecto", e);
            return "Firmante";
        }
    }
    
    private byte[] firmarPdfConPades(byte[] pdfBytes, PrivateKey privateKey, 
                                      Certificate[] chain, String nombreFirmante,
                                      String typeSignature,
                                      String signingPage,
                                      Integer posX, Integer posY,
                                      Integer width, Integer height,
                                      String signingReason,
                                      String signingLocation) 
            throws Exception {
        
        RubricaSigner signer = new PrivateKeySigner(privateKey, DigestAlgorithm.SHA256);
        
        PadesBasic padesSigner = new PadesBasic(signer);
        
        Properties params = new Properties();
        params.setProperty(BaseSigner.SIGNING_REASON, signingReason);
        params.setProperty(BaseSigner.SIGNING_LOCATION, signingLocation);
        params.setProperty(BaseSigner.LAST_PAGE, signingPage);
        params.setProperty(BaseSigner.TYPE_SIG, typeSignature);
        
        int lowerLeftX = posX;
        int lowerLeftY = posY;
        int upperRightX = posX + width;
        int upperRightY = posY + height;
        
        params.setProperty("PositionOnPageLowerLeftX", String.valueOf(lowerLeftX));
        params.setProperty("PositionOnPageLowerLeftY", String.valueOf(lowerLeftY));
        params.setProperty("PositionOnPageUpperRightX", String.valueOf(upperRightX));
        params.setProperty("PositionOnPageUpperRightY", String.valueOf(upperRightY));
        
        if ("QR".equals(typeSignature)) {
            params.setProperty("infoQR", "Firmado digitalmente por: " + nombreFirmante);
        }
        
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pdfBytes);
        
        byte[] signedPdf = padesSigner.sign(inputStream, signer, chain, params);
        
        return signedPdf;
    }
}
