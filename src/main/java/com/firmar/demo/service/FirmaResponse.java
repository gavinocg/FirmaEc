package com.firmar.demo.service;

public class FirmaResponse {
    
    private byte[] pdfFirmado;
    private String nombreFirmante;
    private String fechaFirma;
    private boolean exitoso;
    private String mensaje;
    
    public FirmaResponse() {
    }
    
    public FirmaResponse(byte[] pdfFirmado, String nombreFirmante, String fechaFirma, boolean exitoso, String mensaje) {
        this.pdfFirmado = pdfFirmado;
        this.nombreFirmante = nombreFirmante;
        this.fechaFirma = fechaFirma;
        this.exitoso = exitoso;
        this.mensaje = mensaje;
    }
    
    public byte[] getPdfFirmado() {
        return pdfFirmado;
    }
    
    public void setPdfFirmado(byte[] pdfFirmado) {
        this.pdfFirmado = pdfFirmado;
    }
    
    public String getNombreFirmante() {
        return nombreFirmante;
    }
    
    public void setNombreFirmante(String nombreFirmante) {
        this.nombreFirmante = nombreFirmante;
    }
    
    public String getFechaFirma() {
        return fechaFirma;
    }
    
    public void setFechaFirma(String fechaFirma) {
        this.fechaFirma = fechaFirma;
    }
    
    public boolean isExitoso() {
        return exitoso;
    }
    
    public void setExitoso(boolean exitoso) {
        this.exitoso = exitoso;
    }
    
    public String getMensaje() {
        return mensaje;
    }
    
    public void setMensaje(String mensaje) {
        this.mensaje = mensaje;
    }
}
