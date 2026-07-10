package com.firmar.demo.controller;

import com.firmar.demo.service.FirmaDigitalService;
import com.firmar.demo.service.FirmaResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class FirmaController {
    
    private static final Logger logger = LoggerFactory.getLogger(FirmaController.class);
    
    private final FirmaDigitalService firmaDigitalService;
    
    public FirmaController(FirmaDigitalService firmaDigitalService) {
        this.firmaDigitalService = firmaDigitalService;
    }
    
    @GetMapping("/")
    public String index() {
        return "index";
    }
    
    @PostMapping("/demo/sign")
    public ResponseEntity<byte[]> firmarDocumento(
            @RequestParam("file") MultipartFile pdfFile,
            @RequestParam("certificate") MultipartFile certificadoFile,
            @RequestParam("password") String password,
            @RequestParam(value = "typeSignature", defaultValue = "QR") String typeSignature,
            @RequestParam(value = "signingPage", defaultValue = "1") String signingPage,
            @RequestParam(value = "posX", defaultValue = "50") Integer posX,
            @RequestParam(value = "posY", defaultValue = "50") Integer posY,
            @RequestParam(value = "width", defaultValue = "150") Integer width,
            @RequestParam(value = "height", defaultValue = "150") Integer height,
            @RequestParam(value = "signingReason", defaultValue = "Firma digital de documento") String signingReason,
            @RequestParam(value = "signingLocation", defaultValue = "Ecuador") String signingLocation,
            @RequestParam(value = "additionalPositions", required = false) String additionalPositionsJson) {
        
        logger.info("Recibida solicitud de firma para archivo: {}", pdfFile.getOriginalFilename());
        logger.info("Tipo de firma: {}, Página: {}, Posición: ({}, {}), Tamaño: {}x{}", 
                typeSignature, signingPage, posX, posY, width, height);
        
        try {
            if (pdfFile.isEmpty()) {
                return ResponseEntity.badRequest().body("Error: No se ha proporcionado el archivo PDF".getBytes());
            }
            
            if (certificadoFile.isEmpty()) {
                return ResponseEntity.badRequest().body("Error: No se ha proporcionado el certificado".getBytes());
            }
            
            if (password == null || password.isEmpty()) {
                return ResponseEntity.badRequest().body("Error: No se ha proporcionado la contraseña".getBytes());
            }
            
            FirmaResponse response = firmaDigitalService.firmarPdfMultiple(
                    pdfFile.getBytes(),
                    certificadoFile.getBytes(),
                    password,
                    pdfFile.getOriginalFilename(),
                    typeSignature,
                    signingPage,
                    posX,
                    posY,
                    width,
                    height,
                    signingReason,
                    signingLocation,
                    additionalPositionsJson
            );
            
            String originalFilename = pdfFile.getOriginalFilename();
            String nameWithoutExt = originalFilename.replace(".pdf", "");
            String nombreArchivo = nameWithoutExt + "-signed.pdf";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", nombreArchivo);
            
            logger.info("Documento firmado exitosamente: {}", nombreArchivo);
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(response.getPdfFirmado());
                    
        } catch (Exception e) {
            logger.error("Error al firmar el documento: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(("Error al firmar el documento: " + e.getMessage()).getBytes());
        }
    }
}
